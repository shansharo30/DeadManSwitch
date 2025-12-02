import os
import logging
import threading
import time
from typing import Dict, Optional, Any
from datetime import datetime
from colorama import Fore, Back, Style, init as colorama_init
from database import log_action, get_all_ssh_hosts, get_all_api_hosts, update_ssh_host_status, update_api_host_status
from auth import get_ssh_private_key
from plugins import get_plugin, list_plugins

colorama_init(autoreset=True)

DATA_DIR = os.getenv("DATA_DIR", "./data")
os.makedirs(DATA_DIR, exist_ok=True)
LOG_FILE = os.path.join(DATA_DIR, "dms_app.log")


class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))

logging.basicConfig(level=logging.INFO, handlers=[file_handler, console_handler])
logger = logging.getLogger(__name__)

_shutdown_lock = threading.Lock()
_shutdown_in_progress = False
_shutdown_status = {
    "in_progress": False,
    "started_at": None,
    "phase": None,
    "results": {}
}

_monitoring_thread: Optional[threading.Thread] = None
_monitoring_active = False
_monitoring_interval = int(os.getenv("MONITORING_INTERVAL", "60"))


def test_ssh_connection(host: str, user: str) -> Dict[str, Any]:
    """Test SSH host connection."""
    try:
        plugin = get_plugin("ssh")
        private_key = get_ssh_private_key()
        
        if not private_key:
            return {"success": False, "status": "config_error", "error": "SSH key not found"}
        
        config = {
            "host": host,
            "user": user,
            "private_key": private_key
        }
        
        result = plugin.test_connection(config)
        return {
            "success": result["status"] == "online",
            "status": result["status"],
            "error": result.get("details", "")
        }
        
    except Exception as e:
        logger.error(f"SSH test failed: {e}")
        return {"success": False, "status": "error", "error": str(e)}


def test_api_connection(host: str, api_type: str, api_key: str, api_endpoint: str) -> Dict[str, Any]:
    """Test API host connection."""
    try:
        plugin = get_plugin(api_type)
        
        config = {
            "host": host,
            "api_key": api_key,
            "api_endpoint": api_endpoint
        }
        
        result = plugin.test_connection(config)
        return {
            "success": result["status"] == "online",
            "status": result["status"],
            "error": result.get("details", "")
        }
        
    except Exception as e:
        logger.error(f"API test failed: {e}")
        return {"success": False, "status": "error", "error": str(e)}


def monitor_ssh_host(host_data: Dict) -> None:
    """Monitor single SSH host."""
    host = host_data["host"]
    user = host_data["user"]
    
    try:
        plugin = get_plugin("ssh")
        private_key = get_ssh_private_key()
        
        if not private_key:
            logger.error(f"No SSH private key found for monitoring {user}@{host}")
            update_ssh_host_status(host, user, "error", "No SSH key")
            return
        
        config = {
            "host": host,
            "user": user,
            "private_key": private_key
        }
        
        logger.debug(f"Testing connection to {user}@{host}")
        result = plugin.test_connection(config)
        logger.info(f"Monitor result for {user}@{host}: {result['status']} - {result.get('details', '')}")
        
        update_ssh_host_status(
            host,
            user,
            result["status"],
            result.get("details", "")
        )
        
    except Exception as e:
        logger.error(f"Monitor failed for {user}@{host}: {e}")
        update_ssh_host_status(host, user, "error", str(e))


def monitor_api_host(host_data: Dict) -> None:
    """Monitor single API host."""
    host = host_data["host"]
    api_type = host_data["api_type"]
    
    try:
        plugin = get_plugin(api_type)
        
        config = {
            "host": host,
            "api_key": host_data.get("api_key", ""),
            "api_endpoint": host_data.get("api_endpoint", "")
        }
        
        result = plugin.test_connection(config)
        update_api_host_status(
            host,
            result["status"],
            result.get("details", "")
        )
        
    except Exception as e:
        logger.error(f"Monitor failed for {host}: {e}")
        update_api_host_status(host, "error", str(e))


def monitor_hosts_background() -> None:
    global _monitoring_active
    
    logger.info(f"Starting host monitoring (interval: {_monitoring_interval}s)")
    
    while _monitoring_active:
        try:
            ssh_hosts = get_all_ssh_hosts(enabled_only=False)
            for host in ssh_hosts:
                monitor_ssh_host(host)
            
            api_hosts = get_all_api_hosts(enabled_only=False)
            for host in api_hosts:
                monitor_api_host(host)
            
            from database import cleanup_expired_telegram_sessions
            expired = cleanup_expired_telegram_sessions()
            if expired > 0:
                logger.info(f"Cleaned up {expired} expired telegram sessions")
            
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
        
        time.sleep(_monitoring_interval)


def start_monitoring() -> None:
    """Start background monitoring."""
    global _monitoring_thread, _monitoring_active
    
    if _monitoring_thread and _monitoring_thread.is_alive():
        return
    
    _monitoring_active = True
    _monitoring_thread = threading.Thread(target=monitor_hosts_background, daemon=True)
    _monitoring_thread.start()
    logger.info("Monitoring started")


def stop_monitoring() -> None:
    """Stop background monitoring."""
    global _monitoring_active
    _monitoring_active = False
    logger.info("Monitoring stopped")


def execute_shutdown_phase(hosts: list, plugin_type: str, phase_name: str) -> list:
    """Execute shutdown for a group of hosts."""
    results = []
    
    for host_data in hosts:
        try:
            plugin = get_plugin(plugin_type)
            
            if plugin_type == "ssh":
                private_key = get_ssh_private_key()
                config = {
                    "host": host_data["host"],
                    "user": host_data["user"],
                    "private_key": private_key
                }
            else:
                config = {
                    "host": host_data["host"],
                    "api_key": host_data.get("api_key", ""),
                    "api_endpoint": host_data.get("api_endpoint", "")
                }
            
            result = plugin.execute_shutdown(config)
            results.append(result)
            
            logger.info(f"{phase_name}: {result['host']} - {result['status']}")
            log_action(f"{phase_name}_shutdown", f"{result['host']}: {result['status']}", "DMS", "info")
            
        except Exception as e:
            logger.error(f"{phase_name} failed for {host_data.get('host')}: {e}")
            results.append({
                "host": host_data.get("host"),
                "status": "error",
                "details": str(e)
            })
    
    return results


def initiate_hard_poweroff() -> Dict[str, Any]:
    """Execute shutdown sequence."""
    global _shutdown_in_progress, _shutdown_status
    
    if not _shutdown_lock.acquire(blocking=False):
        return {
            "status": "rejected",
            "message": "Shutdown already in progress",
            "details": _shutdown_status
        }
    
    try:
        _shutdown_in_progress = True
        _shutdown_status = {
            "in_progress": True,
            "started_at": datetime.utcnow().isoformat(),
            "phase": "initialization",
            "results": {}
        }
        
        logger.warning("SHUTDOWN SEQUENCE INITIATED")
        log_action("shutdown_start", "Initiating shutdown", "DMS", "warning")
        
        api_hosts = get_all_api_hosts(enabled_only=True)
        ssh_hosts = get_all_ssh_hosts(enabled_only=True)
        
        vcenter_hosts = [h for h in api_hosts if h.get("api_type") == "vcenter"]
        truenas_hosts = [h for h in api_hosts if h.get("api_type") == "truenas"]
        proxmox_hosts = [h for h in api_hosts if h.get("api_type") == "proxmox"]
        
        results = {}
        
        if vcenter_hosts:
            _shutdown_status["phase"] = "vcenter"
            results["vcenter"] = execute_shutdown_phase(vcenter_hosts, "vcenter", "Phase1")
        
        if truenas_hosts:
            _shutdown_status["phase"] = "truenas"
            results["truenas"] = execute_shutdown_phase(truenas_hosts, "truenas", "Phase2")
        
        if proxmox_hosts:
            _shutdown_status["phase"] = "proxmox_api"
            results["proxmox_api"] = execute_shutdown_phase(proxmox_hosts, "proxmox", "Phase3")
        
        if ssh_hosts:
            _shutdown_status["phase"] = "ssh"
            results["ssh"] = execute_shutdown_phase(ssh_hosts, "ssh", "Phase4")
        
        _shutdown_status["phase"] = "completed"
        _shutdown_status["in_progress"] = False
        _shutdown_status["results"] = results
        
        logger.info("Shutdown sequence completed")
        log_action("shutdown_complete", "All phases finished", "DMS", "success")
        
        return {
            "status": "executed",
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Shutdown failed: {e}")
        _shutdown_status["phase"] = "error"
        _shutdown_status["in_progress"] = False
        return {"status": "error", "details": str(e)}
        
    finally:
        _shutdown_in_progress = False
        _shutdown_lock.release()


def get_shutdown_status() -> Dict:
    """Get current shutdown status."""
    return _shutdown_status.copy()


def is_shutdown_in_progress() -> bool:
    """Check if shutdown is running."""
    return _shutdown_in_progress
