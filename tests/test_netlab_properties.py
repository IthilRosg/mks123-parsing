from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from mks123_pipeline import netlab_properties
from mks123_pipeline.electrozone import FeedValidationError
from mks123_pipeline.netlab_properties import scan_netlab_properties

PROPERTIES_FIXTURE = """<?xml version="1.0" encoding="windows-1251"?>
<xml_catalog date="2026-09-04 08:46">
  <name>Компания Нетлаб</name>
  <properties>
    <property id="p1">Производитель <b>товара</b></property>
    <property id="p2">Модель</property>
  </properties>
  <items>
    <item id="100">
      <p1>ACME</p1>
      <p2>-</p2>
    </item>
    <item id="101">
      <p1>Rex</p1>
    </item>
  </items>
</xml_catalog>
"""


def _write_source(tmp_path: Path, text: str) -> Path:
    source = tmp_path / "GoodsProperties.xml"
    source.write_bytes(text.encode("cp1251"))
    return source


def test_scan_netlab_properties_rejects_observations_before_item_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE)

    class FakeElement:
        def __init__(
            self,
            tag: str,
            *,
            attrib: dict[str, str] | None = None,
            text: str = "",
            children: list[FakeElement] | None = None,
            reject_iteration: bool = False,
        ) -> None:
            self.tag = tag
            self.attrib = attrib or {}
            self.text = text
            self.children = children or []
            self.reject_iteration = reject_iteration

        def __iter__(self):
            if self.reject_iteration:
                raise AssertionError("item children were materialized before the bound check")
            return iter(self.children)

        def itertext(self):
            return iter([self.text])

        def clear(self) -> None:
            return None

    root = FakeElement("xml_catalog", attrib={"date": "2026-09-04 08:46"})
    properties = FakeElement("properties")
    definition = FakeElement("property", attrib={"id": "p1"}, text="Property")
    items = FakeElement("items")
    first = FakeElement("p1", text="first")
    second = FakeElement("p2", text="second")
    item = FakeElement("item", attrib={"id": "100"}, children=[first, second], reject_iteration=True)
    events = [
        ("start", root),
        ("start", properties),
        ("start", definition),
        ("end", definition),
        ("end", properties),
        ("start", items),
        ("start", item),
        ("start", first),
        ("end", first),
        ("start", second),
        ("end", second),
        ("end", item),
    ]
    monkeypatch.setattr(netlab_properties.ET, "iterparse", lambda *_args, **_kwargs: iter(events))

    with pytest.raises(FeedValidationError, match="observation count exceeds maximum"):
        netlab_properties.scan_netlab_properties(
            source,
            max_bytes=64 * 1024,
            max_observations=1,
        )



def test_scan_netlab_properties_does_not_count_nested_item_markup_before_structure_error(
    tmp_path: Path,
) -> None:
    source = _write_source(
        tmp_path,
        PROPERTIES_FIXTURE.replace(
            "<p1>ACME</p1>",
            "<p1><item><b>ACME</b></item></p1>",
        ),
    )

    with pytest.raises(FeedValidationError, match="item must be a direct child of items"):
        scan_netlab_properties(
            source,
            max_bytes=64 * 1024,
            max_observations=1,
        )



def test_scan_netlab_properties_streams_definitions_and_items(tmp_path: Path) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE)
    observations: list[tuple[str, str, str, str, bool]] = []

    stats = scan_netlab_properties(
        source,
        max_bytes=64 * 1024,
        emit=lambda observation: observations.append(
            (
                observation.item_id,
                observation.property_id,
                observation.property_name,
                observation.value,
                observation.missing,
            )
        ),
    )

    assert stats.catalog_date == "2026-09-04 08:46"
    assert stats.source_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert stats.property_count == 2
    assert stats.item_count == 2
    assert stats.observation_count == 3
    assert stats.missing_observation_count == 1
    assert observations == [
        ("100", "p1", "Производитель товара", "ACME", False),
        ("100", "p2", "Модель", "-", True),
        ("101", "p1", "Производитель товара", "Rex", False),
    ]


def test_scan_netlab_properties_rejects_unknown_property(tmp_path: Path) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE.replace("<p1>ACME</p1>", "<p999>ACME</p999>"))

    with pytest.raises(FeedValidationError, match="unknown property p999"):
        scan_netlab_properties(source, max_bytes=64 * 1024)


def test_scan_netlab_properties_can_preserve_unknown_property_as_review_only(tmp_path: Path) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE.replace("<p1>ACME</p1>", "<p999>ACME</p999>"))
    observations = []

    stats = scan_netlab_properties(
        source,
        max_bytes=64 * 1024,
        allow_unknown_property_ids=True,
        emit=observations.append,
    )

    assert stats.unknown_property_id_count == 1
    assert stats.unknown_observation_count == 1
    assert observations[0].property_name is None
    assert observations[0].definition_missing is True


def test_scan_netlab_properties_rejects_duplicate_property_tag(tmp_path: Path) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE.replace("<p2>-</p2>", "<p2>-</p2><p2>other</p2>"))

    with pytest.raises(FeedValidationError, match="duplicate property p2"):
        scan_netlab_properties(source, max_bytes=64 * 1024)



def test_scan_netlab_properties_accepts_official_archive_and_seals_archive(tmp_path: Path) -> None:
    source = tmp_path / "GoodsProperties.zip"
    with ZipFile(source, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("GoodsProperties.xml", PROPERTIES_FIXTURE.encode("cp1251"))

    stats = scan_netlab_properties(source, max_bytes=64 * 1024)

    assert stats.source_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert stats.item_count == 2


@pytest.mark.parametrize(
    ("bound", "message"),
    [
        ("max_properties", "property definition count exceeds maximum"),
        ("max_items", "item count exceeds maximum"),
        ("max_observations", "observation count exceeds maximum"),
    ],
)
def test_scan_netlab_properties_enforces_collection_bounds(
    tmp_path: Path,
    bound: str,
    message: str,
) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE)
    with pytest.raises(FeedValidationError, match=message):
        scan_netlab_properties(source, max_bytes=64 * 1024, **{bound: 1})


def test_scan_netlab_properties_accepts_exact_collection_bounds(tmp_path: Path) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE)
    stats = scan_netlab_properties(
        source,
        max_bytes=64 * 1024,
        max_properties=2,
        max_items=2,
        max_observations=3,
    )
    assert stats.property_count == 2
    assert stats.item_count == 2
    assert stats.observation_count == 3


@pytest.mark.parametrize(
    "invalid_bound",
    [0, -1, True, 1.5, "1"],
)
@pytest.mark.parametrize("bound", ["max_properties", "max_items", "max_observations"])
def test_scan_netlab_properties_rejects_invalid_collection_bounds(
    tmp_path: Path,
    bound: str,
    invalid_bound: object,
) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE)
    with pytest.raises(FeedValidationError, match="parser bound"):
        scan_netlab_properties(source, max_bytes=64 * 1024, **{bound: invalid_bound})


@pytest.mark.parametrize("container", ["properties", "items"])
def test_scan_netlab_properties_rejects_containers_without_required_root_ancestry(
    tmp_path: Path,
    container: str,
) -> None:
    malformed = PROPERTIES_FIXTURE.replace(
        f"  <{container}>",
        f"  <wrapper>\n    <{container}>",
    ).replace(
        f"  </{container}>",
        f"    </{container}>\n  </wrapper>",
    )
    source = _write_source(tmp_path, malformed)

    with pytest.raises(FeedValidationError, match="must be a direct child"):
        scan_netlab_properties(source, max_bytes=64 * 1024)
