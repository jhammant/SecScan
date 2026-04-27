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


# ---- complete_json: response-body parse failures must surface as LMStudioError ----
#
# Previously a malformed HTTP body from LM Studio (truncated stream, html error
# page, etc.) raised a raw `json.JSONDecodeError` from httpx's `r.json()`,
# which leaked past every `except LMStudioError` in the codebase and killed
# whole arch / synth passes. Observed live on a chia-blockchain rerun where
# both arch_error and synth_error showed identical `Expecting ',' delimiter:
# line 45 column 6` messages — the format of an unwrapped JSONDecodeError.

class _StubResponse:
    def __init__(self, status_code: int, json_payload=None, text: str = "",
                 raise_on_json: Exception | None = None) -> None:
        self.status_code = status_code
        self._json = json_payload
        self.text = text
        self._raise_on_json = raise_on_json

    def json(self):
        if self._raise_on_json is not None:
            raise self._raise_on_json
        return self._json


class _StubHTTP:
    def __init__(self, response: _StubResponse) -> None:
        self.response = response

    def post(self, *_a, **_kw):
        return self.response


def _client_with(response: _StubResponse):
    """Build an LMStudioClient with `_http` swapped for a stub. Avoids a real
    socket and lets us simulate exactly the bad responses we want to test."""
    from secscan.lmstudio_client import LMStudioClient
    c = LMStudioClient(model="stub-model")
    c._http = _StubHTTP(response)
    return c


def test_complete_json_wraps_response_body_jsondecodeerror():
    """If httpx's r.json() raises (truncated/garbled HTTP body), complete_json
    must surface it as LMStudioError, not a raw JSONDecodeError."""
    import json as _json
    bad_resp = _StubResponse(
        status_code=200,
        raise_on_json=_json.JSONDecodeError("Expecting ',' delimiter", "doc", 100),
    )
    c = _client_with(bad_resp)
    with pytest.raises(LMStudioError, match="Malformed LM Studio response body"):
        c.complete_json("system", "user")


def test_complete_json_wraps_unexpected_response_shape():
    """If LM Studio returns valid JSON but the choices/message/content path is
    missing, that's still a malformed response — surface as LMStudioError."""
    bad_resp = _StubResponse(
        status_code=200,
        json_payload={"choices": []},  # missing [0].message.content
    )
    c = _client_with(bad_resp)
    with pytest.raises(LMStudioError, match="Malformed LM Studio response body"):
        c.complete_json("system", "user")


def test_complete_json_passes_through_good_response():
    """Sanity: stub a clean OpenAI-shaped response; complete_json returns the
    parsed JSON content unchanged."""
    good_resp = _StubResponse(
        status_code=200,
        json_payload={"choices": [{"message": {"content": '{"ok": true}'}}]},
    )
    c = _client_with(good_resp)
    assert c.complete_json("system", "user") == {"ok": True}
