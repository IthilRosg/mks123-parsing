from __future__ import annotations

import json
from decimal import Decimal

import pytest

from mks123_pipeline.conflict_policy import classify_conflict, classify_preview
from scripts.run_conflict_queue_policy import (
    _read_source_snapshot,
    build_artifact,
    main,
)


def row(source: str, name: str, value: str, *, state: str = "source_backed", visible: bool = True) -> dict:
    return {
        "source": source,
        "name": name,
        "value": value,
        "value_state": state,
        "customer_visible": visible,
    }


def test_placeholder_internal_field_is_removed_from_human_queue() -> None:
    decision = classify_conflict(
        "Сайт производителя",
        [row("clone", "Сайт производителя", "Сайт производителя", state="placeholder", visible=False)],
        [row("netlab", "Сайт производителя", "https://example.test", visible=False)],
    )
    assert decision.action == "auto_hide_internal_or_placeholder"
    assert decision.human_review is False


def test_usb_version_is_normalized_to_status_format() -> None:
    decision = classify_conflict(
        "Версия",
        [row("clone", "Версия", "2")],
        [row("netlab", "Версия", "2.0")],
    )
    assert decision.action == "normalization_candidate"
    assert decision.normalized_value == "2.0"
    assert decision.human_review is False


def test_black_color_is_normalized_without_semantic_change() -> None:
    decision = classify_conflict(
        "Цвет чернил",
        [row("clone", "Цвет чернил", "Чёрный (Black)")],
        [row("netlab", "Цвет чернил", "Черный")],
    )
    assert decision.action == "normalization_candidate"
    assert decision.normalized_value == "Чёрный"


def test_weight_within_three_percent_preserves_current_and_needs_no_item_review() -> None:
    decision = classify_conflict(
        "Вес брутто грамм",
        [row("clone", "Вес брутто (грамм)", "3.07 кг")],
        [row("netlab", "Вес брутто грамм", "3100")],
        tolerance=Decimal("0.03"),
    )
    assert decision.action == "within_tolerance_preserve_current"
    assert decision.human_review is False
    assert decision.delta_percent is not None
    assert decision.evidence_required is False


def test_dimensions_never_use_percent_tolerance_automatically() -> None:
    decision = classify_conflict(
        "Глубина, мм",
        [row("clone", "Глубина (мм)", "450")],
        [row("netlab", "Глубина, мм", "451")],
        tolerance=Decimal("0.03"),
    )
    assert decision.action == "grouped_manufacturer_or_packaging_review"
    assert decision.human_review is True
    assert decision.evidence_required is True


def test_documentation_and_compatibility_are_grouped_not_item_exceptions() -> None:
    documentation = classify_conflict(
        "Инструкция",
        [row("clone", "Инструкция", "Инструкция")],
        [row("netlab", "Инструкция", "https://example.test/manual.pdf")],
    )
    compatibility = classify_conflict(
        "Совместимые модели",
        [row("clone", "Совместимые модели", "P1005")],
        [row("netlab", "Совместимые модели", "P1005")],
    )
    assert documentation.action == "grouped_documentation_review"
    assert documentation.human_review is True
    assert compatibility.action == "grouped_compatibility_review"
    assert compatibility.human_review is True


def test_preview_classification_counts_and_groups_by_action() -> None:
    items = [
        {
            "catalog_sku": "A",
            "name": "A",
            "characteristic_comparison": [
                {
                    "name": "Версия",
                    "status": "conflict",
                    "clone": [row("clone", "Версия", "2")],
                    "netlab": [row("netlab", "Версия", "2.0")],
                }
            ],
        },
        {
            "catalog_sku": "B",
            "name": "B",
            "characteristic_comparison": [
                {
                    "name": "Инструкция",
                    "status": "conflict",
                    "clone": [row("clone", "Инструкция", "Инструкция")],
                    "netlab": [row("netlab", "Инструкция", "https://example.test/manual.pdf")],
                }
            ],
        },
    ]
    result = classify_preview(items)
    assert result.summary["conflict_entries"] == 2
    assert result.summary["actions"]["normalization_candidate"] == 1
    assert result.summary["actions"]["grouped_documentation_review"] == 1
    assert result.summary["items_with_any_review_after_filter"] == 1
    assert result.grouped_skus["grouped_documentation_review"] == {"B"}


def test_build_artifact_binds_input_hash_and_no_write_guarantees(tmp_path) -> None:
    preview = tmp_path / "preview.json"
    preview_bytes = b'{"items": []}\n'
    preview.write_bytes(preview_bytes)
    _, source_hashes = _read_source_snapshot()
    artifact = build_artifact(preview, preview_bytes, [], Decimal("0.03"), source_hashes)
    assert artifact["input_preview_sha256"]
    assert artifact["policy_module_sha256"]
    assert artifact["runner_sha256"]
    assert artifact["read_only"] is True
    assert artifact["production_writes"] == 0
    assert artifact["publication_enabled"] is False
    assert artifact["compatibility_relations_created"] == 0


@pytest.mark.parametrize("raw", ["NaN", "Infinity", "0", "0.009", "0.031"])
def test_tolerance_rejects_non_finite_or_out_of_policy_values(raw: str) -> None:
    with pytest.raises(ValueError):
        classify_preview([], tolerance=Decimal(raw))


def test_multiple_source_values_do_not_use_only_the_first_row() -> None:
    decision = classify_conflict(
        "Версия",
        [row("clone", "Версия", "2"), row("clone", "Версия", "3")],
        [row("netlab", "Версия", "2.0")],
    )
    assert decision.action == "item_exception_review"
    assert decision.human_review is True


def test_mixed_unknown_and_visible_values_are_not_hidden() -> None:
    decision = classify_conflict(
        "Страна",
        [row("clone", "Страна", "Россия"), row("clone", "Страна", "-", state="unknown", visible=False)],
        [row("netlab", "Страна", "Китай")],
    )
    assert decision.action == "grouped_dictionary_review"
    assert decision.human_review is True


def test_missing_value_state_is_schema_exception() -> None:
    bad = row("clone", "Артикул", "AB-12")
    bad.pop("value_state")
    decision = classify_conflict("Артикул", [bad], [row("netlab", "Артикул", "AB12")])
    assert decision.action == "item_exception_review"
    assert decision.evidence_required is True


def test_identifier_punctuation_is_not_normalized_as_a_fact() -> None:
    decision = classify_conflict(
        "Артикул",
        [row("clone", "Артикул", "AB-12")],
        [row("netlab", "Артикул", "AB12")],
    )
    assert decision.action == "item_exception_review"


def test_weight_parser_rejects_ranges_and_unsupported_units() -> None:
    for value in ("3.07 кг (упаковка 4 кг)", "6 lb"):
        decision = classify_conflict(
            "Вес брутто грамм",
            [row("clone", "Вес брутто", value)],
            [row("netlab", "Вес брутто грамм", "3100")],
        )
        assert decision.action == "grouped_manufacturer_or_packaging_review"


def test_mixed_placeholder_version_does_not_normalize() -> None:
    decision = classify_conflict(
        "Версия",
        [row("clone", "Версия", "2"), row("clone", "Версия", "-", state="placeholder", visible=False)],
        [row("netlab", "Версия", "2.0")],
    )
    assert decision.action == "item_exception_review"


def test_surface_punctuation_is_not_erased() -> None:
    decision = classify_conflict(
        "Тип поверхности для печати",
        [row("clone", "Тип поверхности для печати", "A-B")],
        [row("netlab", "Тип поверхности для печати", "AB")],
    )
    assert decision.action == "item_exception_review"


def test_weight_unit_substring_and_object_conflict_are_not_accepted() -> None:
    for clone_name, clone_value in (("Вес игрового устройства", "3100"), ("Вес упаковки без товара", "3100")):
        decision = classify_conflict(
            "Вес",
            [row("clone", clone_name, clone_value)],
            [row("netlab", "Вес товара с упаковкой", "3101")],
        )
        assert decision.action == "grouped_manufacturer_or_packaging_review"


def test_non_scalar_value_is_schema_exception() -> None:
    decision = classify_conflict(
        "Вес",
        [row("clone", "Вес", "3100") | {"value": [3100]}],
        [row("netlab", "Вес", "3101")],
    )
    assert decision.action == "item_exception_review"


def test_malformed_preview_schema_is_rejected() -> None:
    with pytest.raises(TypeError):
        classify_preview([{"catalog_sku": "A", "characteristic_comparison": {}}])


def test_color_with_extra_punctuation_is_not_normalized() -> None:
    decision = classify_conflict(
        "Цвет",
        [row("clone", "Цвет", "black+")],
        [row("netlab", "Цвет", "black")],
    )
    assert decision.action == "item_exception_review"


def test_numeric_weight_value_is_classified_without_attribute_error() -> None:
    decision = classify_conflict(
        "Вес брутто грамм",
        [row("clone", "Вес брутто", 3100)],
        [row("netlab", "Вес брутто грамм", "3101")],
    )
    assert decision.action == "within_tolerance_preserve_current"


def test_same_status_rows_are_schema_validated() -> None:
    with pytest.raises(TypeError):
        classify_preview(
            [
                {
                    "catalog_sku": "A",
                    "characteristic_comparison": [
                        {
                            "name": "Поле",
                            "status": "same",
                            "clone": [{"name": None, "value": [], "value_state": "invalid", "customer_visible": "yes"}],
                            "netlab": [{"name": None, "value": [], "value_state": "invalid", "customer_visible": "yes"}],
                        }
                    ],
                }
            ]
        )


def test_weight_word_units_and_version_strings_are_strict() -> None:
    weight = classify_conflict(
        "Вес брутто килограмм",
        [row("clone", "Вес брутто килограмм", "3")],
        [row("netlab", "Вес брутто килограмм", "3 г")],
    )
    version = classify_conflict(
        "Версия",
        [row("clone", "Версия", "+2")],
        [row("netlab", "Версия", "2.0")],
    )
    assert weight.action == "grouped_manufacturer_or_packaging_review"
    assert version.action == "item_exception_review"


def test_cli_refuses_existing_output_without_clobber(tmp_path) -> None:
    preview = tmp_path / "preview.json"
    preview.write_text('{"items": []}\n', encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    with pytest.raises(SystemExit) as exc:
        main(["--preview", str(preview), "--output", str(output), "--tolerance", "0.03"])
    assert exc.value.code == 2
    assert list(output.iterdir()) == []


def test_cli_success_writes_committed_manifest_and_no_staging(tmp_path) -> None:
    preview = tmp_path / "preview.json"
    preview.write_text('{"items": []}\n', encoding="utf-8")
    output = tmp_path / "out"
    assert main(["--preview", str(preview), "--output", str(output), "--tolerance", "0.03"]) == 0
    assert sorted(path.name for path in output.iterdir()) == ["COMMITTED", "QUEUE_DRY_RUN.json", "REPORT.md"]
    marker = json.loads((output / "COMMITTED").read_text(encoding="utf-8"))
    for name, info in marker["files"].items():
        data = (output / name).read_bytes()
        assert len(data) == info["size"]
    assert not list(tmp_path.glob(".out.*"))
