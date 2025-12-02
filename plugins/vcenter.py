import ssl
import logging
from typing import Dict, Any
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from plugins.base import PluginBase

logger = logging.getLogger(__name__)


class VCenterPlugin(PluginBase):
    """Plugin for VMware vCenter/ESXi management."""
    
    @property
    def plugin_type(self) -> str:
        return "vcenter"
    
    def test_connection(self, config: Dict[str, Any]) -> Dict[str, str]:
        host = config.get("host", "")
        username = config.get("api_key", "")
        password = config.get("api_endpoint", "")
        
        if not all([host, username, password]):
            missing = [k for k, v in {"host": host, "api_key": username, "api_endpoint": password}.items() if not v]
            logger.error(f"vCenter test_connection missing fields: {', '.join(missing)}")
            return {"status": "error", "details": "Missing required configuration"}
        
        try:
            logger.debug(f"Attempting vCenter connect: host={host}, user_present={bool(username)}, pwd_present={bool(password)}")
            try:
                pwd_len = len(password)
                pwd_trailing_ws = password.endswith((" ", "\t", "\r", "\n"))
                logger.debug(f"vCenter creds summary: user_len={len(username)}, pwd_len={pwd_len}, pwd_trailing_ws={pwd_trailing_ws}")
            except Exception:
                pass
            context = ssl._create_unverified_context()
            si = SmartConnect(
                host=host,
                user=username,
                pwd=password,
                port=443,
                sslContext=context
            )
            logger.info(f"vCenter connection established to {host}")
            Disconnect(si)
            return {"status": "online", "details": "Connection successful"}
        except Exception as e:
            msg = str(e)
            logger.error(f"vCenter test_connection error for {host}: {type(e).__name__}: {msg}")
            if "incorrect" in msg.lower() or "auth" in msg.lower() or "login" in msg.lower():
                return {"status": "auth_failed", "details": "Invalid credentials"}
            return {"status": "error", "details": msg}
    
    def execute_shutdown(self, config: Dict[str, Any]) -> Dict[str, Any]:
        host = config.get("host", "")
        username = config.get("api_key", "")
        password = config.get("api_endpoint", "")
        
        result = {"host": host, "status": "unknown", "details": ""}
        
        if not all([host, username, password]):
            missing = [k for k, v in {"host": host, "api_key": username, "api_endpoint": password}.items() if not v]
            logger.error(f"vCenter execute_shutdown missing fields: {', '.join(missing)}")
            result["status"] = "error"
            result["details"] = "Missing required configuration"
            return result
        
        try:
            logger.debug(f"Attempting vCenter shutdown: host={host}, user_present={bool(username)}, pwd_present={bool(password)}")
            try:
                pwd_len = len(password)
                pwd_trailing_ws = password.endswith((" ", "\t", "\r", "\n"))
                logger.debug(f"vCenter creds summary: user_len={len(username)}, pwd_len={pwd_len}, pwd_trailing_ws={pwd_trailing_ws}")
            except Exception:
                pass
            context = ssl._create_unverified_context()
            si = SmartConnect(
                host=host,
                user=username,
                pwd=password,
                port=443,
                sslContext=context
            )
            logger.info(f"vCenter connection established to {host} for shutdown phase")
            
            content = si.RetrieveContent()
            
            # Step 1: Get all VMs and power them off
            vm_view = content.viewManager.CreateContainerView(
                content.rootFolder,
                [vim.VirtualMachine],
                True
            )
            vms = vm_view.view
            vm_view.Destroy()
            
            vms_powered_off = 0
            vms_failed = 0
            for vm in vms:
                try:
                    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
                        logger.info(f"Powering off VM: {vm.name}")
                        task = vm.PowerOffVM_Task()
                        # Wait for task completion
                        while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
                            pass
                        if task.info.state == vim.TaskInfo.State.success:
                            vms_powered_off += 1
                            logger.info(f"VM {vm.name} powered off successfully")
                        else:
                            vms_failed += 1
                            logger.error(f"Failed to power off VM {vm.name}: {task.info.error}")
                    else:
                        logger.debug(f"VM {vm.name} already powered off")
                except Exception as vm_error:
                    vms_failed += 1
                    logger.error(f"Error powering off VM {vm.name}: {type(vm_error).__name__}: {vm_error}")
            
            logger.info(f"VMs powered off: {vms_powered_off}, failed: {vms_failed}")
            
            # Step 2: Get all ESXi hosts and shut them down immediately
            host_view = content.viewManager.CreateContainerView(
                content.rootFolder,
                [vim.HostSystem],
                True
            )
            hosts = host_view.view
            host_view.Destroy()
            
            hosts_shutdown = 0
            hosts_failed = 0
            for esxi_host in hosts:
                try:
                    logger.info(f"Forcing immediate shutdown of ESXi host: {esxi_host.name}")
                    
                    # Force immediate shutdown - no maintenance mode, no graceful shutdown
                    esxi_host.ShutdownHost_Task(force=True)
                    hosts_shutdown += 1
                    logger.info(f"Forced shutdown initiated for {esxi_host.name}")
                    
                except Exception as host_error:
                    hosts_failed += 1
                    logger.error(f"Error shutting down ESXi host {esxi_host.name}: {type(host_error).__name__}: {host_error}")
            
            logger.info(f"ESXi hosts shutdown: {hosts_shutdown}, failed: {hosts_failed}")
            
            # Build result summary
            total_vms = vms_powered_off + vms_failed
            total_hosts = hosts_shutdown + hosts_failed
            
            if hosts_failed == 0 and vms_failed == 0:
                result["status"] = "success"
                result["details"] = f"Shutdown complete: {vms_powered_off} VMs powered off, {hosts_shutdown} ESXi hosts shutdown"
            elif hosts_shutdown > 0 or vms_powered_off > 0:
                result["status"] = "partial"
                result["details"] = f"Partial shutdown: {vms_powered_off}/{total_vms} VMs, {hosts_shutdown}/{total_hosts} hosts"
            else:
                result["status"] = "error"
                result["details"] = f"Shutdown failed: {vms_failed} VM errors, {hosts_failed} host errors"
            
            Disconnect(si)
            
        except Exception as e:
            msg = str(e)
            logger.error(f"vCenter execute_shutdown error for {host}: {type(e).__name__}: {msg}")
            result["status"] = "error"
            result["details"] = msg
        
        return result
    
    def get_required_fields(self) -> Dict[str, str]:
        return {
            "host": "vCenter hostname or IP",
            "api_key": "vSphere username",
            "api_endpoint": "vSphere password"
        }
