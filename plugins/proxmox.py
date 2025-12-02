import logging
import requests
from typing import Dict, Any
from plugins.base import PluginBase

logger = logging.getLogger(__name__)


class ProxmoxPlugin(PluginBase):
    """Plugin for Proxmox management."""
    
    @property
    def plugin_type(self) -> str:
        return "proxmox"
    
    def test_connection(self, config: Dict[str, Any]) -> Dict[str, str]:
        host = config.get("host", "")
        api_key = config.get("api_key", "")
        
        try:
            response = requests.get(
                f"https://{host}:8006/api2/json/version",
                headers={"Authorization": f"PVEAPIToken={api_key}"},
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                return {"status": "online", "details": "Connection successful"}
            elif response.status_code == 401:
                return {"status": "auth_failed", "details": "Invalid API token"}
            else:
                return {"status": "error", "details": f"HTTP {response.status_code}"}
                
        except requests.exceptions.Timeout:
            return {"status": "timeout", "details": "Connection timeout"}
        except Exception as e:
            return {"status": "error", "details": str(e)}
    
    def execute_shutdown(self, config: Dict[str, Any]) -> Dict[str, Any]:
        host = config.get("host", "")
        api_key = config.get("api_key", "")
        node = config.get("node", "pve")
        
        result = {"host": host, "status": "unknown", "details": ""}
        
        try:
            response = requests.post(
                f"https://{host}:8006/api2/json/nodes/{node}/status",
                headers={"Authorization": f"PVEAPIToken={api_key}"},
                json={"command": "shutdown"},
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                result["status"] = "shutdown_initiated"
                result["details"] = "Shutdown command sent"
            else:
                result["status"] = "failed"
                result["details"] = f"HTTP {response.status_code}"
                
        except Exception as e:
            result["status"] = "error"
            result["details"] = str(e)
        
        return result
    
    def get_required_fields(self) -> Dict[str, str]:
        return {
            "host": "Proxmox hostname or IP",
            "api_key": "Proxmox API token",
            "api_endpoint": "Node name (default: pve)"
        }
