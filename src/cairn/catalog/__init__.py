"""Device catalog: locally-managed, strictly-validated anchoring records."""

from cairn.catalog.device_catalog import (
    CATALOG_KIND,
    CATALOG_SCHEMA_VERSION,
    MAX_HMAC_KEY_BYTES,
    MIN_HMAC_KEY_BYTES,
    CatalogError,
    DeviceCatalog,
    DeviceEntry,
    PackageEntry,
    RollbackBound,
    load_catalog,
    load_catalog_verified,
    parse_catalog,
    sign_catalog_bytes,
)

__all__ = [
    "CATALOG_KIND",
    "CATALOG_SCHEMA_VERSION",
    "MAX_HMAC_KEY_BYTES",
    "MIN_HMAC_KEY_BYTES",
    "CatalogError",
    "DeviceCatalog",
    "DeviceEntry",
    "PackageEntry",
    "RollbackBound",
    "load_catalog",
    "load_catalog_verified",
    "parse_catalog",
    "sign_catalog_bytes",
]
