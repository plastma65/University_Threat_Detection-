"""
Normalizer Registry - Centralized Dispatch

Provides centralized mechanism for dispatching log lines to appropriate
normalizer based on log source type.
"""

from typing import Dict, Optional

from .base import LogNormalizer
from .implementations.nginx import NginxLogNormalizer
from .implementations.auth import AuthLogNormalizer
from .implementations.firewall import FirewallLogNormalizer
from .implementations.fastapi import FastAPILogNormalizer
from .implementations.postgres import PostgresLogNormalizer
from .implementations.secrepo_auth import SecrepoAuthLogNormalizer
from .implementations.web_scanner import WebScannerLogNormalizer
from .implementations.realworld_firewall import RealworldFirewallLogNormalizer
from .implementations.unsw_nb15 import UNSWNB15Normalizer
from .implementations.cicids2017 import CICIDS2017Normalizer


class NormalizerRegistry:
    """
    Centralized registry for log normalizers.
    
    Maps log source types to their corresponding normalizer instances.
    Provides get_normalizer() method for dispatching log lines.
    
    Uses singleton pattern to ensure only one registry instance exists.
    """
    
    def __init__(self):
        """Initialize registry with actual normalizers."""
        self._normalizers: Dict[str, LogNormalizer] = {}
        self._initialize_normalizers()
    
    def _initialize_normalizers(self) -> None:
        """
        Initialize all supported normalizers.
        """
        self._normalizers = {
            "nginx": NginxLogNormalizer(),
            "auth": AuthLogNormalizer(),
            "firewall": FirewallLogNormalizer(),
            "postgres": PostgresLogNormalizer(),
            "api": FastAPILogNormalizer(),
            "secrepo_auth": SecrepoAuthLogNormalizer(),
            "web_scanner": WebScannerLogNormalizer(),
            "firewall_realworld": RealworldFirewallLogNormalizer(),
            "unsw-nb15": UNSWNB15Normalizer(),
            "cicids2017": CICIDS2017Normalizer(),
        }

    
    def register(self, source: str, normalizer: LogNormalizer) -> None:
        """
        Register a normalizer for a specific log source.
        
        Args:
            source: Log source type (e.g., "nginx", "auth")
            normalizer: Normalizer instance to register
            
        Raises:
            ValueError: If source is not in supported sources
        """
        supported_sources = {"nginx", "auth", "firewall", "postgres", "api", "secrepo_auth", "web_scanner", "firewall_realworld", "unsw-nb15", "cicids2017"}
        if source not in supported_sources:
            raise ValueError(f"Unsupported source: {source}. Must be one of: {supported_sources}")
        
        self._normalizers[source] = normalizer
    
    def get_normalizer(self, source: str) -> Optional[LogNormalizer]:
        """
        Get the normalizer for a specific log source.
        
        Args:
            source: Log source type (e.g., "nginx", "auth")
            
        Returns:
            Normalizer instance if registered, None if not yet implemented
            
        Raises:
            ValueError: If source is not in supported sources
        """
        supported_sources = {"nginx", "auth", "firewall", "postgres", "api", "secrepo_auth", "web_scanner", "firewall_realworld", "unsw-nb15", "cicids2017"}
        if source not in supported_sources:
            raise ValueError(f"Unsupported source: {source}. Must be one of: {supported_sources}")
        
        return self._normalizers[source]
    
    def get_supported_sources(self) -> set:
        """
        Get the set of supported log source types.
        
        Returns:
            Set of supported source names
        """
        return set(self._normalizers.keys())
    
    def is_registered(self, source: str) -> bool:
        """
        Check if a normalizer is registered for a source.
        
        Args:
            source: Log source type to check
            
        Returns:
            True if normalizer is registered (not None), False otherwise
        """
        return self._normalizers.get(source) is not None


# Singleton instance for module-level access
_registry_instance: Optional[NormalizerRegistry] = None


def get_registry() -> NormalizerRegistry:
    """
    Get the singleton NormalizerRegistry instance.
    
    Returns:
        The singleton registry instance
    """
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = NormalizerRegistry()
    return _registry_instance
