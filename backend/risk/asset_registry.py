"""
Asset Registry Module
---------------------
Defines enterprise company assets, their criticality tiers, business owners,
and endpoint pattern bindings.

Asset Criticality Levels & Weights:
- CRITICAL (Weight: 1.0) : High impact on financial operations, authentication, or sensitive data.
- HIGH     (Weight: 0.8) : Core operational APIs and customer portals.
- MEDIUM   (Weight: 0.6) : Search features, marketing catalog, public queries.
- LOW      (Weight: 0.4) : Static informational pages, assets, about docs.
"""

from typing import Dict, Any, List, Optional

# Default Enterprise Asset Registry
DEFAULT_ASSETS = [
    {
        "id": "asset-auth-01",
        "name": "Identity & Access Gateway",
        "type": "Authentication Service",
        "criticality": "CRITICAL",
        "weight": 1.0,
        "endpoint_pattern": "/login",
        "description": "Central authentication gateway handling user logins, session tokens, and admin access.",
        "data_classification": "Restricted (Credentials & Sessions)",
        "business_unit": "Security & Identity"
    },
    {
        "id": "asset-pay-02",
        "name": "Payment & Order Checkout API",
        "type": "Financial Gateway",
        "criticality": "CRITICAL",
        "weight": 1.0,
        "endpoint_pattern": "/cart/checkout",
        "description": "Processes payment transactions, billing addresses, and order confirmations.",
        "data_classification": "Confidential (PCI-DSS Financial)",
        "business_unit": "Finance Operations"
    },
    {
        "id": "asset-admin-03",
        "name": "Administrative Management Console",
        "type": "Management Portal",
        "criticality": "CRITICAL",
        "weight": 0.95,
        "endpoint_pattern": "/admin",
        "description": "Internal administration panel controlling product records, user roles, and system configuration.",
        "data_classification": "Restricted (Internal Config)",
        "business_unit": "Core Platform Ops"
    },
    {
        "id": "asset-api-04",
        "name": "Product Catalog API",
        "type": "REST Data Service",
        "criticality": "HIGH",
        "weight": 0.8,
        "endpoint_pattern": "/api",
        "description": "Microservice serving product inventory, pricing, and inventory updates.",
        "data_classification": "Internal Business Data",
        "business_unit": "E-Commerce Core"
    },
    {
        "id": "asset-search-05",
        "name": "Customer Search & Discovery Service",
        "type": "Search Service",
        "criticality": "MEDIUM",
        "weight": 0.6,
        "endpoint_pattern": "/search",
        "description": "Public search engine allowing customers to query products, categories, and tags.",
        "data_classification": "Public / Read-Only",
        "business_unit": "Customer Experience"
    },
    {
        "id": "asset-web-06",
        "name": "Public Storefront Website",
        "type": "Web Portal",
        "criticality": "LOW",
        "weight": 0.4,
        "endpoint_pattern": "/",
        "description": "Public storefront landing page, promotional banners, and static informational assets.",
        "data_classification": "Public",
        "business_unit": "Marketing"
    }
]

class AssetRegistry:
    def __init__(self, initial_assets: Optional[List[Dict[str, Any]]] = None):
        self._assets: List[Dict[str, Any]] = initial_assets or DEFAULT_ASSETS.copy()

    def get_all_assets(self) -> List[Dict[str, Any]]:
        return self._assets

    def get_asset_by_id(self, asset_id: str) -> Optional[Dict[str, Any]]:
        for asset in self._assets:
            if asset["id"] == asset_id:
                return asset
        return None

    def match_asset_by_endpoint(self, path: str) -> Dict[str, Any]:
        """
        Matches an incoming request path to the most specific registered enterprise asset.
        """
        if not path:
            return self._assets[-1]  # Default to Public Storefront

        path_clean = path.lower().strip()

        # Prioritize exact and specific sub-path matches
        if "/login" in path_clean:
            return self._get_by_id("asset-auth-01")
        if "/checkout" in path_clean or "/cart" in path_clean:
            return self._get_by_id("asset-pay-02")
        if "/admin" in path_clean or "/server-status" in path_clean or "/.env" in path_clean:
            return self._get_by_id("asset-admin-03")
        if "/api" in path_clean:
            return self._get_by_id("asset-api-04")
        if "/search" in path_clean:
            return self._get_by_id("asset-search-05")

        # Fallback to general storefront
        return self._get_by_id("asset-web-06")

    def _get_by_id(self, asset_id: str) -> Dict[str, Any]:
        for asset in self._assets:
            if asset["id"] == asset_id:
                return asset
        return self._assets[-1]

# Global singleton
asset_registry_instance = AssetRegistry()
