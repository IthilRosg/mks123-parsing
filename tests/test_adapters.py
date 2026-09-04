import pytest

from mks123_pipeline.adapters import create_adapter


def test_create_adapter_resolves_registered_supplier_and_scope() -> None:
    adapter = create_adapter("electrozone", expected_catalog_sku_prefix="11")

    assert adapter.supplier_id == "electrozone"
    assert adapter.catalog_sku_prefix == "11"


def test_create_adapter_rejects_unknown_supplier() -> None:
    with pytest.raises(ValueError, match="no adapter registered"):
        create_adapter("supplier-b", expected_catalog_sku_prefix="31")


def test_create_adapter_rejects_scope_mismatch() -> None:
    with pytest.raises(ValueError, match="SKU prefix"):
        create_adapter("electrozone", expected_catalog_sku_prefix="31")
