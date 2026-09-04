from pathlib import Path

import pytest

from mks123_pipeline.runner import _load_catalog

HEADER = [
    "product_id",
    "model",
    "sku",
    "ean",
    "name",
    "manufacturer",
    "price",
    "quantity",
    "status",
    "category_ids",
    "categories",
]


def test_load_catalog_rejects_duplicate_headers(tmp_path: Path) -> None:
    path = tmp_path / "catalog.csv"
    path.write_text(
        "product_id,model,sku,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"
        "1,M,110,999,,Name,Brand,10,1,1,,\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate catalog header"):
        _load_catalog(path, sku_prefix="11")
