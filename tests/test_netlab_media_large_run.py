import hashlib
import json
from pathlib import Path

from mks123_pipeline.integrity import build_run_seal
from mks123_pipeline.netlab_media import build_media_plan


def test_media_plan_streams_full_size_normalized_artifact(tmp_path: Path) -> None:
    run = tmp_path / 'source-run'
    normalized = run / 'normalized'
    normalized.mkdir(parents=True)
    selected = {
        'supplier': 'netlab',
        'supplier_item_id': 'selected-1',
        'catalog_sku': 'selected-1',
        'image_urls': ['https://nlimg.netlab.ru/selected.jpg'],
    }
    filler = {
        'supplier': 'netlab',
        'supplier_item_id': 'filler',
        'catalog_sku': 'filler',
        'image_urls': [],
        'description': 'x' * (1024 * 1024),
    }
    with (normalized / 'items.jsonl').open('w', encoding='utf-8') as handle:
        handle.write(json.dumps(selected) + '\n')
        for _ in range(257):
            handle.write(json.dumps(filler) + '\n')
    assert (normalized / 'items.jsonl').stat().st_size > 256 * 1024 * 1024
    (run / 'run-manifest.json').write_text(json.dumps({
        'run_id': 'large-source-run',
        'supplier': 'netlab',
        'publication_enabled': False,
        'production_writes': 0,
    }) + '\n', encoding='utf-8')
    build_run_seal(run)
    source_seal_sha256 = hashlib.sha256((run / 'seal.json').read_bytes()).hexdigest()
    plan = build_media_plan(run, {
        'eligible_catalog_skus': ['selected-1'],
        'eligible_supplier_item_ids': [],
        'max_images_per_item': 1,
        'transform': {
            'format': 'webp',
            'quality': 84,
            'hero_max_edge': 1600,
            'gallery_max_edge': 1200,
            'no_upscale': True,
            'strip_metadata': True,
        },
    }, expected_source_seal_sha256=source_seal_sha256)
    assert plan['counts'] == {'selected_images': 1}
    assert plan['fetches'][0]['catalog_sku'] == 'selected-1'
