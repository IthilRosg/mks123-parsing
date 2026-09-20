from __future__ import annotations

import hashlib
import io
import json
import os
import stat
from pathlib import Path

import pytest
from PIL import Image

from mks123_pipeline.integrity import build_run_seal
from mks123_pipeline.netlab_media import (
    MAX_COMPRESSED_BYTES,
    build_media_plan,
    canonical_selection_policy,
    stage_media_plan,
    validate_image,
)
from mks123_pipeline.netlab_media_finalize import (
    finalize_media_stage,
    init_storage,
    verify_media_run,
)


def image(size: tuple[int, int] = (2000, 1000), fmt: str = "PNG") -> bytes:
    out = io.BytesIO()
    Image.new("RGB", size, (12, 34, 56)).save(out, fmt)
    return out.getvalue()


def source_run(path: Path) -> Path:
    (path / "normalized").mkdir(parents=True)
    rows = [
        {"supplier": "netlab", "supplier_item_id": "i1", "catalog_sku": "s1",
         "image_urls": ["https://nlimg.netlab.ru/a.png", "https://nlimg.netlab.ru/b.png", "https://nlimg.netlab.ru/c.png"]},
        {"supplier": "netlab", "supplier_item_id": "i2", "catalog_sku": "s2",
         "image_urls": ["https://nlimg.netlab.ru/d.png"]},
    ]
    (path / "normalized/items.jsonl").write_text("".join(json.dumps(x) + "\n" for x in rows), encoding="utf-8")
    (path / "run-manifest.json").write_text(json.dumps({"run_id": "source-1", "supplier": "netlab",
        "publication_enabled": False, "production_writes": 0}) + "\n", encoding="utf-8")
    build_run_seal(path)
    return path


def policy(*, quality: int = 84) -> dict[str, object]:
    return {"eligible_catalog_skus": ["s1"], "eligible_supplier_item_ids": [], "max_images_per_item": 2,
            "transform": {"format": "webp", "quality": quality, "hero_max_edge": 1600,
                          "gallery_max_edge": 1200, "no_upscale": True, "strip_metadata": True}}


def setup(tmp_path: Path) -> tuple[Path, Path, dict[str, object], str]:
    source = source_run(tmp_path / "source")
    root = tmp_path / "media"
    init_storage(root, writer_uid=1001, writer_gid=1001, test_only_allow_unenforced=True)
    plan = build_media_plan(source, policy())
    plan_sha = hashlib.sha256((json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
    return source, root, plan, plan_sha


def test_original_policy_accepts_source_format_and_preserves_the_selection_contract(tmp_path: Path) -> None:
    original_policy = {
        "eligible_catalog_skus": ["s1"],
        "eligible_supplier_item_ids": [],
        "max_images_per_item": 2,
        "transform": {"format": "source", "preserve_original": True},
    }
    canonical = canonical_selection_policy(original_policy)
    assert canonical["transform"] == {"format": "source", "preserve_original": True}
    plan = build_media_plan(source_run(tmp_path / "source"), original_policy)
    assert plan["transform_policy"] == canonical["transform"]


def test_original_policy_stages_and_finalizes_source_bytes_without_reencoding(tmp_path: Path) -> None:
    original_policy = {
        "eligible_catalog_skus": ["s1"],
        "eligible_supplier_item_ids": [],
        "max_images_per_item": 2,
        "transform": {"format": "source", "preserve_original": True},
    }
    source = source_run(tmp_path / "source")
    root = tmp_path / "media"
    init_storage(root, writer_uid=1001, writer_gid=1001, test_only_allow_unenforced=True)
    plan = build_media_plan(source, original_policy)
    plan_sha = hashlib.sha256(_canonical(plan)).hexdigest()
    original = image((20, 10), fmt="WEBP")
    staged = stage_media_plan(
        plan,
        media_root=root,
        stage_id="original",
        expected_plan_sha256=plan_sha,
        fetcher=lambda url, **kw: {"data": original, "metadata": validate_image(original, content_type="image/webp")},
        test_only_allow_unenforced=True,
    )
    manifest = json.loads((Path(staged["stage_dir"]) / "stage-manifest.json").read_text())
    assert all(obj["output"] == {key: obj["source"][key] for key in ("format", "width", "height", "size_bytes", "sha256")} for obj in manifest["objects"])
    assert all(Path(obj["stage_path"]).suffix == ".webp" for obj in manifest["objects"])
    assert all((Path(staged["stage_dir"]) / obj["stage_path"]).read_bytes() == original for obj in manifest["objects"])
    final = finalize_media_stage(
        media_root=root,
        stage_id="original",
        media_run_id="original-run",
        expected_stage_seal_sha256=staged["stage_seal_sha256"],
        expected_plan_sha256=plan_sha,
        test_only_allow_unenforced=True,
    )
    assert verify_media_run(root, "original-run", final["media_seal_sha256"], source_run_dir=source,
                            test_only_allow_unenforced=True)["verified"] is True



def test_policy_is_generic_exact_allowlist_and_empty_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least one"):
        canonical_selection_policy(policy() | {"eligible_catalog_skus": []})
    source = source_run(tmp_path / "source")
    plan = build_media_plan(source, policy())
    assert [x["catalog_sku"] for x in plan["fetches"]] == ["s1", "s1"]
    assert [x["slot"] for x in plan["fetches"]] == [0, 1]
    canonical = canonical_selection_policy(policy())
    assert plan["selection_policy_sha256"] == hashlib.sha256(
        (json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()


def test_stage_transforms_deterministically_and_never_writes_cas_or_runs(tmp_path: Path) -> None:
    _, root, plan, plan_sha = setup(tmp_path)
    original = image()
    fetch = lambda url, **kw: {"data": original, "metadata": validate_image(original, content_type="image/png")}
    first = stage_media_plan(plan, media_root=root, stage_id="a", expected_plan_sha256=plan_sha,
                             fetcher=fetch, test_only_allow_unenforced=True)
    second = stage_media_plan(plan, media_root=root, stage_id="b", expected_plan_sha256=plan_sha,
                              fetcher=fetch, test_only_allow_unenforced=True)
    a = json.loads((Path(first["stage_dir"]) / "stage-manifest.json").read_text())
    b = json.loads((Path(second["stage_dir"]) / "stage-manifest.json").read_text())
    assert [x["output"] for x in a["objects"]] == [x["output"] for x in b["objects"]]
    assert [x["output"]["width"] for x in a["objects"]] == [1600, 1200]
    for obj in a["objects"]:
        payload = (Path(first["stage_dir"]) / obj["stage_path"]).read_bytes()
        assert payload[:4] == b"RIFF" and original not in payload
        assert obj["source"]["sha256"] == hashlib.sha256(original).hexdigest()
        assert "perceptual_hash" in obj and "similarity_evidence" in obj
    assert not any((root / "cas").glob("*/*"))
    assert not any((root / "runs").iterdir())
    assert not any(p.suffix in {".png", ".jpg", ".jpeg"} for p in (root / "staging").rglob("*"))


def test_compressed_and_pixel_limits_are_predecode(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="compressed"):
        validate_image(b"x" * (MAX_COMPRESSED_BYTES + 1), content_type="image/png")
    oversized = image((5000, 4000))
    def forbidden(self: Image.Image, *args: object, **kwargs: object) -> object:
        raise AssertionError("must reject before decode")
    monkeypatch.setattr(Image.Image, "load", forbidden)
    with pytest.raises(ValueError, match="pre-decode"):
        validate_image(oversized, content_type="image/png")


def test_stage_mutation_is_rejected_before_finalization(tmp_path: Path) -> None:
    _, root, plan, plan_sha = setup(tmp_path)
    data = image((20, 10))
    staged = stage_media_plan(plan, media_root=root, stage_id="s", expected_plan_sha256=plan_sha,
        fetcher=lambda url, **kw: {"data": data, "metadata": validate_image(data, content_type="image/png")},
        test_only_allow_unenforced=True)
    target = next((Path(staged["stage_dir"]) / "objects").iterdir())
    target.write_bytes(b"changed")
    with pytest.raises(ValueError, match="size/hash"):
        finalize_media_stage(media_root=root, stage_id="s", media_run_id="r",
            expected_stage_seal_sha256=staged["stage_seal_sha256"], expected_plan_sha256=plan_sha,
            test_only_allow_unenforced=True)


def test_finalize_copies_no_hardlinks_rejects_collision_and_verifies(tmp_path: Path) -> None:
    source, root, plan, plan_sha = setup(tmp_path)
    data = image((20, 10))
    staged = stage_media_plan(plan, media_root=root, stage_id="s", expected_plan_sha256=plan_sha,
        fetcher=lambda url, **kw: {"data": data, "metadata": validate_image(data, content_type="image/png")},
        test_only_allow_unenforced=True)
    final = finalize_media_stage(media_root=root, stage_id="s", media_run_id="r",
        expected_stage_seal_sha256=staged["stage_seal_sha256"], expected_plan_sha256=plan_sha,
        test_only_allow_unenforced=True)
    manifest = json.loads((Path(final["run_dir"]) / "media-manifest.json").read_text())
    stage_obj = Path(staged["stage_dir"]) / manifest["objects"][0]["stage_path"]
    cas_obj = root / manifest["objects"][0]["cas_path"]
    assert stage_obj.stat().st_ino != cas_obj.stat().st_ino
    assert Path(staged["stage_dir"]).exists()
    assert verify_media_run(root, "r", final["media_seal_sha256"], source_run_dir=source,
                            test_only_allow_unenforced=True)["verified"] is True
    with pytest.raises(FileExistsError):
        finalize_media_stage(media_root=root, stage_id="s", media_run_id="r",
            expected_stage_seal_sha256=staged["stage_seal_sha256"], expected_plan_sha256=plan_sha,
            test_only_allow_unenforced=True)


def test_verifier_two_read_mutation_fails(tmp_path: Path) -> None:
    source, root, plan, plan_sha = setup(tmp_path)
    data = image((20, 10))
    staged = stage_media_plan(plan, media_root=root, stage_id="s", expected_plan_sha256=plan_sha,
        fetcher=lambda url, **kw: {"data": data, "metadata": validate_image(data, content_type="image/png")},
        test_only_allow_unenforced=True)
    final = finalize_media_stage(media_root=root, stage_id="s", media_run_id="r",
        expected_stage_seal_sha256=staged["stage_seal_sha256"], expected_plan_sha256=plan_sha,
        test_only_allow_unenforced=True)
    manifest_path = Path(final["run_dir"]) / "media-manifest.json"
    def mutate() -> None:
        os.chmod(manifest_path, 0o600)
        manifest_path.write_text("{}\n")
    with pytest.raises(ValueError):
        verify_media_run(root, "r", final["media_seal_sha256"], source_run_dir=source,
                         between_reads=mutate, test_only_allow_unenforced=True)


@pytest.mark.skipif(os.name == "nt", reason="POSIX umask semantics")
def test_storage_modes_ignore_umask(tmp_path: Path) -> None:
    old = os.umask(0)
    try:
        init_storage(tmp_path / "m", writer_uid=1001, writer_gid=1001, test_only_allow_unenforced=True)
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "m").stat().st_mode) == 0o750
    assert stat.S_IMODE((tmp_path / "m/staging").stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o730 for p in (tmp_path / "m/cas").iterdir())


@pytest.mark.parametrize("failed", [{0}, {1}, {0, 2}])
def test_mixed_fetch_outcomes_preserve_original_fetch_indexes(tmp_path: Path, failed: set[int]) -> None:
    source, root, plan, plan_sha = setup(tmp_path)
    if len(plan["fetches"]) < 3:
        plan["fetches"].append({"url": "https://nlimg.netlab.ru/c.png", "supplier_item_id": "i1",
                                "catalog_sku": "s1", "slot": 2, "role": "gallery"})
        plan["counts"]["selected_images"] = len(plan["fetches"])
        plan_sha = hashlib.sha256((json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
    data = image((20, 10))
    indexes = {item["url"]: i for i, item in enumerate(plan["fetches"])}
    def fetch(url: str, **_: object) -> dict[str, object]:
        if indexes[url] in failed:
            raise TimeoutError("injected")
        return {"data": data, "metadata": validate_image(data, content_type="image/png")}
    staged = stage_media_plan(plan, media_root=root, stage_id="mixed", expected_plan_sha256=plan_sha,
                              fetcher=fetch, test_only_allow_unenforced=True)
    manifest = json.loads((Path(staged["stage_dir"]) / "stage-manifest.json").read_text())
    assert {x["fetch_index"] for x in manifest["objects"] + manifest["failures"]} == set(range(len(plan["fetches"])))
    assert all(Path(x["stage_path"]).name.startswith(f"{x['fetch_index']:06d}-") for x in manifest["objects"])
    final = finalize_media_stage(media_root=root, stage_id="mixed", media_run_id="mixed-run",
                                 expected_stage_seal_sha256=staged["stage_seal_sha256"],
                                 expected_plan_sha256=plan_sha, test_only_allow_unenforced=True)
    assert verify_media_run(root, "mixed-run", final["media_seal_sha256"], source_run_dir=source,
                            test_only_allow_unenforced=True)["verified"] is True


def test_stage_rejects_path_substitution_without_touching_replacement(tmp_path: Path) -> None:
    _, root, plan, plan_sha = setup(tmp_path)
    data = image((20, 10))
    original = root / "staging" / "swap"
    displaced = root / "staging" / "displaced"
    def fetch(url: str, **_: object) -> dict[str, object]:
        if not displaced.exists():
            original.rename(displaced)
            original.mkdir()
            (original / "sentinel").write_text("outside")
        return {"data": data, "metadata": validate_image(data, content_type="image/png")}
    with pytest.raises(ValueError, match="substitut"):
        stage_media_plan(plan, media_root=root, stage_id="swap", expected_plan_sha256=plan_sha,
                         fetcher=fetch, test_only_allow_unenforced=True)
    assert (original / "sentinel").read_text() == "outside"
    assert displaced.exists()
    assert [entry.name for entry in displaced.iterdir()] == ["objects"]
    assert not any((displaced / "objects").iterdir())


def _canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("mutation", ["source", "output", "transform", "phash", "similarity", "failure"])
def test_finalizer_rejects_resealed_nested_stage_mutations(tmp_path: Path, mutation: str) -> None:
    _, root, plan, plan_sha = setup(tmp_path)
    data = image((20, 10))
    first_url = plan["fetches"][0]["url"]
    def fetch(url: str, **_: object) -> dict[str, object]:
        if url != first_url:
            raise TimeoutError("injected")
        return {"data": data, "metadata": validate_image(data, content_type="image/png")}
    staged = stage_media_plan(plan, media_root=root, stage_id="bad", expected_plan_sha256=plan_sha,
                              fetcher=fetch, test_only_allow_unenforced=True)
    stage = Path(staged["stage_dir"])
    manifest_path = stage / "stage-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    obj = manifest["objects"][0]
    if mutation == "source": obj["source"]["width"] = 0
    elif mutation == "output": obj["output"]["height"] = 0
    elif mutation == "transform": obj["transform"]["max_edge"] += 1
    elif mutation == "phash": obj["perceptual_hash"] = "z" * 16
    elif mutation == "similarity": obj["similarity_evidence"] = [{"object_index": 0, "hamming_distance": 0}]
    else: manifest["failures"][0]["binding"]["url"] = first_url
    manifest_bytes = _canonical(manifest)
    manifest_path.write_bytes(manifest_bytes)
    seal_path = stage / "stage-seal.json"
    seal = json.loads(seal_path.read_text())
    seal["files"]["stage-manifest.json"]["size"] = len(manifest_bytes)
    seal["files"]["stage-manifest.json"]["sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    seal_bytes = _canonical(seal)
    seal_path.write_bytes(seal_bytes)
    with pytest.raises(ValueError):
        finalize_media_stage(media_root=root, stage_id="bad", media_run_id=f"bad-{mutation}",
                             expected_stage_seal_sha256=hashlib.sha256(seal_bytes).hexdigest(),
                             expected_plan_sha256=plan_sha, test_only_allow_unenforced=True)


@pytest.mark.parametrize("mutation", ["source", "output", "transform", "phash", "similarity", "cas_created"])
def test_verifier_rejects_resealed_nested_final_mutations(tmp_path: Path, mutation: str) -> None:
    source, root, plan, plan_sha = setup(tmp_path)
    data = image((20, 10))
    staged = stage_media_plan(plan, media_root=root, stage_id="ok", expected_plan_sha256=plan_sha,
                              fetcher=lambda url, **kw: {"data": data, "metadata": validate_image(data, content_type="image/png")},
                              test_only_allow_unenforced=True)
    final = finalize_media_stage(media_root=root, stage_id="ok", media_run_id="bad-final",
                                 expected_stage_seal_sha256=staged["stage_seal_sha256"],
                                 expected_plan_sha256=plan_sha, test_only_allow_unenforced=True)
    run = Path(final["run_dir"])
    manifest_path = run / "media-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    obj = manifest["objects"][0]
    if mutation == "source": obj["source"]["extra"] = 1
    elif mutation == "output": obj["output"]["width"] = 0
    elif mutation == "transform": obj["transform"]["format"] = "png"
    elif mutation == "phash": obj["perceptual_hash"] = "F" * 16
    elif mutation == "similarity": manifest["objects"][1]["similarity_evidence"][0]["hamming_distance"] += 1
    else: obj["cas_created"] = 1
    manifest_bytes = _canonical(manifest)
    os.chmod(manifest_path, 0o600)
    manifest_path.write_bytes(manifest_bytes)
    seal_path = run / "media-seal.json"
    seal = json.loads(seal_path.read_text())
    seal["files"]["media-manifest.json"]["size"] = len(manifest_bytes)
    seal["files"]["media-manifest.json"]["sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    seal_bytes = _canonical(seal)
    os.chmod(seal_path, 0o600)
    seal_path.write_bytes(seal_bytes)
    with pytest.raises(ValueError):
        verify_media_run(root, "bad-final", hashlib.sha256(seal_bytes).hexdigest(), source_run_dir=source,
                         test_only_allow_unenforced=True)
