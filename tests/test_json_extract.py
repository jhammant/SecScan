import pytest

from secscan.lmstudio_client import (
    LMStudioError,
    _extract_json,
    _repair_json,
    _strip_trailing_commas,
)


def test_plain_json():
    assert _extract_json('{"findings": []}') == {"findings": []}


def test_fenced_json():
    raw = 'Here you go:\n```json\n{"findings": [1]}\n```\n'
    assert _extract_json(raw) == {"findings": [1]}


def test_noisy_json():
    raw = 'thinking...\n{"findings": [{"x": 1}]}\ntrailing noise'
    assert _extract_json(raw) == {"findings": [{"x": 1}]}


# ---- repair: missing comma between siblings ----

def test_repair_missing_comma_between_array_objects():
    # Classic 27B failure: dropped comma between two sibling objects
    raw = '{"components": [{"name": "a"} {"name": "b"}]}'
    assert _extract_json(raw) == {"components": [{"name": "a"}, {"name": "b"}]}


def test_repair_missing_comma_between_object_fields():
    raw = '{"name": "foo" "role": "bar"}'
    assert _extract_json(raw) == {"name": "foo", "role": "bar"}


def test_repair_missing_comma_after_array():
    raw = '{"a": [1, 2] "b": 3}'
    assert _extract_json(raw) == {"a": [1, 2], "b": 3}


def test_repair_missing_comma_in_nested_arrays():
    raw = '{"x": [[1, 2] [3, 4]]}'
    assert _extract_json(raw) == {"x": [[1, 2], [3, 4]]}


# ---- repair: trailing commas ----

def test_repair_trailing_comma_in_object():
    assert _extract_json('{"a": 1, "b": 2,}') == {"a": 1, "b": 2}


def test_repair_trailing_comma_in_array():
    assert _extract_json('{"x": [1, 2, 3,]}') == {"x": [1, 2, 3]}


def test_repair_trailing_comma_with_whitespace():
    raw = '{"x": [1, 2, 3 ,\n  ]}'
    assert _extract_json(raw) == {"x": [1, 2, 3]}


# ---- repair: comments ----

def test_repair_strips_line_comments():
    raw = '{\n  "a": 1, // a comment\n  "b": 2\n}'
    assert _extract_json(raw) == {"a": 1, "b": 2}


def test_repair_strips_block_comments():
    raw = '{"a": 1, /* explanation */ "b": 2}'
    assert _extract_json(raw) == {"a": 1, "b": 2}


# ---- safety: don't corrupt strings ----

def test_strip_trailing_commas_preserves_string_contents():
    # The "," followed by "]" inside the string must NOT be removed
    raw = '{"note": "trailing, here ]", "x": 1}'
    assert _strip_trailing_commas(raw) == raw


def test_repair_preserves_double_slash_inside_string():
    # The "//" inside a string is a URL, not a comment
    raw = '{"url": "https://example.com/path", "x": 1}'
    assert _extract_json(raw) == {"url": "https://example.com/path", "x": 1}


def test_repair_preserves_escaped_quote_in_string():
    raw = r'{"q": "she said \"hi\"", "n": 2}'
    assert _extract_json(raw) == {"q": 'she said "hi"', "n": 2}


# ---- combined glitches ----

def test_repair_combined_glitches():
    raw = '''
    Here is the JSON:
    ```json
    {
      "components": [
        {"name": "api"} // first
        {"name": "worker",}
      ],
      "trust_boundaries": [{"description": "boundary",}],
    }
    ```
    '''
    result = _extract_json(raw)
    assert result == {
        "components": [{"name": "api"}, {"name": "worker"}],
        "trust_boundaries": [{"description": "boundary"}],
    }


# ---- bounded failure ----

def test_unrepairable_raises_lmstudio_error():
    with pytest.raises(LMStudioError):
        _extract_json("not json at all, no braces")


def test_repair_bounded_passes_does_not_loop():
    # Pathological input: not valid JSON, but iterative repair shouldn't hang
    bad = "{" * 200
    # Should return some string and not hang; downstream will raise LMStudioError
    result = _repair_json(bad, max_passes=5)
    assert isinstance(result, str)
