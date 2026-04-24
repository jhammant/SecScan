from secscan.lmstudio_client import _extract_json


def test_plain_json():
    assert _extract_json('{"findings": []}') == {"findings": []}


def test_fenced_json():
    raw = 'Here you go:\n```json\n{"findings": [1]}\n```\n'
    assert _extract_json(raw) == {"findings": [1]}


def test_noisy_json():
    raw = 'thinking...\n{"findings": [{"x": 1}]}\ntrailing noise'
    assert _extract_json(raw) == {"findings": [{"x": 1}]}
