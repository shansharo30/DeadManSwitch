import importlib
import pkgutil
import logging
from typing import Dict, Type
from plugins.base import PluginBase

logger = logging.getLogger(__name__)

_plugin_registry: Dict[str, Type[PluginBase]] = {}


def discover_plugins():
    """Discover and register all available plugins."""
    global _plugin_registry
    
    import plugins
    
    loaded_plugins = []
    
    for _, module_name, _ in pkgutil.iter_modules(plugins.__path__):
        if module_name == "base" or module_name == "__init__":
            continue
        
        try:
            module = importlib.import_module(f"plugins.{module_name}")
            
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                
                if (isinstance(attr, type) and 
                    issubclass(attr, PluginBase) and 
                    attr is not PluginBase):
                    
                    instance = attr()
                    plugin_type = instance.plugin_type
                    _plugin_registry[plugin_type] = attr
                    loaded_plugins.append(plugin_type)
                    logger.info(f"Registered plugin: {plugin_type}")
                    
        except Exception as e:
            logger.error(f"Failed to load plugin {module_name}: {e}")
    
    if loaded_plugins:
        print(f"\n✓ Loaded plugins: {', '.join(loaded_plugins)}")
    else:
        print("\n⚠ No plugins loaded")


def get_plugin(plugin_type: str) -> PluginBase:
    """Get plugin instance by type."""
    if not _plugin_registry:
        discover_plugins()
    
    plugin_class = _plugin_registry.get(plugin_type)
    if not plugin_class:
        raise ValueError(f"Unknown plugin type: {plugin_type}")
    
    return plugin_class()


def list_plugins() -> list:
    """List all available plugin types."""
    if not _plugin_registry:
        discover_plugins()
    
    return list(_plugin_registry.keys())
