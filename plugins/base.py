from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class PluginBase(ABC):
    """Base class for target system plugins."""
    
    @property
    @abstractmethod
    def plugin_type(self) -> str:
        """Unique identifier for this plugin type."""
        pass
    
    @abstractmethod
    def test_connection(self, config: Dict[str, Any]) -> Dict[str, str]:
        """
        Test connection to target system.
        
        Args:
            config: Connection configuration (host, credentials, etc.)
            
        Returns:
            Dict with 'status' (online/offline/auth_failed/timeout/error) and 'details'
        """
        pass
    
    @abstractmethod
    def execute_shutdown(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute shutdown on target system.
        
        Args:
            config: Connection configuration
            
        Returns:
            Dict with 'host', 'status', and 'details'
        """
        pass
    
    def supports_monitoring(self) -> bool:
        """Whether this plugin supports background monitoring."""
        return True
    
    def get_required_fields(self) -> Dict[str, str]:
        """
        Return required configuration fields.
        
        Returns:
            Dict mapping field names to descriptions
        """
        return {
            "host": "Target hostname or IP address",
            "api_key": "Authentication key or username",
            "api_endpoint": "API endpoint or password"
        }
