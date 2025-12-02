import logging
import subprocess
import tempfile
from typing import Dict, Any
from plugins.base import PluginBase

logger = logging.getLogger(__name__)


class SSHPlugin(PluginBase):
    """Plugin for SSH-based management (Linux, macOS, Windows)."""
    
    @property
    def plugin_type(self) -> str:
        return "ssh"
    
    def _get_shutdown_commands(self, config: Dict[str, Any]) -> list:
        """Detect OS and return list of shutdown commands to try (in priority order)."""
        host = config.get("host", "")
        user = config.get("user", "")
        private_key = config.get("private_key", "")
        
        # Try to detect OS
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as key_file:
                key_file.write(private_key)
                key_path = key_file.name
            
            # Fix permissions: SSH requires 600 (owner read/write only)
            import os
            os.chmod(key_path, 0o600)
            
            result = subprocess.run(
                [
                    "ssh",
                    "-i", key_path,
                    "-o", "ConnectTimeout=5",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "BatchMode=yes",
                    f"{user}@{host}",
                    "uname -s"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10
            )
            
            subprocess.run(["rm", "-f", key_path], check=False)
            
            if result.returncode == 0:
                os_name = result.stdout.decode().strip().lower()
                if "darwin" in os_name:
                    # macOS
                    return ["sudo /sbin/shutdown -h now"]
                elif "linux" in os_name:
                    # Linux
                    return ["sudo /sbin/shutdown -h now"]
                elif "mingw" in os_name or "msys" in os_name or "cygwin" in os_name:
                    # Windows
                    return ["shutdown /s /t 0"]
        except:
            pass
        
        # Default fallback for Unix-like systems
        return ["sudo /sbin/shutdown -h now"]
    
    def test_connection(self, config: Dict[str, Any]) -> Dict[str, str]:
        host = config.get("host", "")
        user = config.get("user", "")
        private_key = config.get("private_key", "")
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as key_file:
                key_file.write(private_key)
                key_path = key_file.name
            
            # Fix permissions: SSH requires 600 (owner read/write only)
            import os
            os.chmod(key_path, 0o600)
            
            result = subprocess.run(
                [
                    "ssh",
                    "-i", key_path,
                    "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "BatchMode=yes",
                    f"{user}@{host}",
                    "echo test"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15
            )
            
            subprocess.run(["rm", "-f", key_path], check=False)
            
            if result.returncode == 0:
                return {"status": "online", "details": "Connection successful"}
            else:
                error_msg = result.stderr.decode().strip()
                logger.warning(f"SSH test failed for {user}@{host}: {error_msg}")
                if "permission denied" in error_msg.lower():
                    return {"status": "auth_failed", "details": "Authentication failed"}
                return {"status": "error", "details": error_msg}
                
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "details": "Connection timeout"}
        except Exception as e:
            return {"status": "error", "details": str(e)}
    
    def execute_shutdown(self, config: Dict[str, Any]) -> Dict[str, Any]:
        host = config.get("host", "")
        user = config.get("user", "")
        private_key = config.get("private_key", "")
        
        # Get list of commands to try (auto-detected based on OS)
        commands = self._get_shutdown_commands(config)
        
        result = {"host": host, "status": "unknown", "details": ""}
        errors = []
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as key_file:
                key_file.write(private_key)
                key_path = key_file.name
            
            # Fix permissions: SSH requires 600 (owner read/write only)
            import os
            os.chmod(key_path, 0o600)
            
            # Try each command until one succeeds
            for command in commands:
                logger.info(f"Trying shutdown command on {host}: {command}")
                
                proc = subprocess.run(
                    [
                        "ssh",
                        "-i", key_path,
                        "-o", "ConnectTimeout=10",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "BatchMode=yes",
                        f"{user}@{host}",
                        command
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30
                )
                
                if proc.returncode == 0:
                    result["status"] = "shutdown_initiated"
                    result["details"] = f"Success with: {command}"
                    logger.info(f"Shutdown initiated on {host} with: {command}")
                    break
                else:
                    stderr = proc.stderr.decode().strip()
                    errors.append(f"{command}: {stderr or 'no output'}")
                    logger.warning(f"Command '{command}' failed on {host}: {stderr}")
            else:
                # All commands failed
                result["status"] = "failed"
                result["details"] = "All shutdown commands failed: " + "; ".join(errors)
                logger.error(f"SSH shutdown failed for {user}@{host}: {result['details']}")
            
            subprocess.run(["rm", "-f", key_path], check=False)
                
        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            result["details"] = "Command may be executing (timeout)"
        except Exception as e:
            result["status"] = "error"
            result["details"] = str(e)
        
        return result
    
    def get_required_fields(self) -> Dict[str, str]:
        return {
            "host": "Target hostname or IP",
            "user": "SSH username",
            "private_key": "SSH private key"
        }
