from typing import Dict, Optional, Type

from artemis.config.schema import AppConfig, ModelConfig
from .base import ModelProvider


class ModelRegistry:
    """Registry for instantiating and looking up models by their assigned role."""
    
    _provider_classes: Dict[str, Type[ModelProvider]] = {}
    
    @classmethod
    def register_provider(cls, provider_name: str, provider_cls: Type[ModelProvider]) -> None:
        """Register a provider implementation class."""
        cls._provider_classes[provider_name] = provider_cls

    def __init__(self, config: AppConfig):
        self._providers_by_role: Dict[str, ModelProvider] = {}
        self._configs_by_role: Dict[str, ModelConfig] = {}
        
        for model_cfg in config.models:
            if model_cfg.role in self._providers_by_role:
                raise ValueError(f"Duplicate role '{model_cfg.role}' defined in models config.")
                
            provider_cls = self._provider_classes.get(model_cfg.provider)
            if not provider_cls:
                raise ValueError(f"Unknown provider '{model_cfg.provider}' for model '{model_cfg.id}'")
                
            # Instantiate the provider passing the specific config.
            provider = provider_cls(config=model_cfg)
            self._providers_by_role[model_cfg.role] = provider
            self._configs_by_role[model_cfg.role] = model_cfg
            
    def get_provider(self, role: str) -> Optional[ModelProvider]:
        """Get the instantiated provider for a given role."""
        return self._providers_by_role.get(role)

    def get_config(self, role: str) -> Optional[ModelConfig]:
        """Get the configuration for a given role."""
        return self._configs_by_role.get(role)

    def get_all_roles(self) -> list[str]:
        """Return a list of all configured roles."""
        return list(self._providers_by_role.keys())
