"""Thin wrapper around LMStudio: SDK for inference, `lms` CLI for model mgmt."""
from __future__ import annotations
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class ModelInfo:
    identifier: str
    loaded: bool = False
    type: str | None = None  # llm | embedding
    size: str | None = None


class LMStudioError(RuntimeError):
    pass


class LMStudioClient:
    """Inference via the OpenAI-compatible endpoint LMStudio exposes.

    The `lmstudio` Python SDK is the preferred interface, but the OpenAI-compatible
    REST surface keeps dependencies light and is what `lms server start` exposes.
    We use the `lms` CLI (if installed) to list/load models.
    """

    def __init__(self, host: str = "localhost:1234", model: str | None = None):
        self.host = host
        self.model = model
        self._http = httpx.Client(
            base_url=f"http://{host}/v1",
            # 30-min read timeout: a single architecture/synthesis call on a 27B
            # reasoning model at 32k context can easily exceed 10 min on Apple
            # Silicon. Calls that genuinely hang are still bounded.
            timeout=httpx.Timeout(connect=5.0, read=1800.0, write=30.0, pool=30.0),
        )
        # Cache of the response_format shape this model accepts; set on first success.
        self._json_mode: dict | None = None

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "LMStudioClient":
        return self

    def __exit__(self, *a) -> None:
        self.close()

    # ---------- Server health ----------

    def health(self) -> bool:
        try:
            r = self._http.get("/models")
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    # ---------- Model management ----------

    def list_models(self) -> list[ModelInfo]:
        """Prefer `lms ls` when present (shows loaded state); fall back to /v1/models."""
        if shutil.which("lms"):
            try:
                return _parse_lms_ls(_run(["lms", "ls"]))
            except LMStudioError:
                pass
        r = self._http.get("/models")
        r.raise_for_status()
        return [ModelInfo(identifier=m["id"], loaded=True) for m in r.json().get("data", [])]

    def load_model(self, identifier: str) -> None:
        """Load a model via `lms load`. No-op if CLI missing (assume user pre-loaded)."""
        if not shutil.which("lms"):
            return
        _run(["lms", "load", identifier, "--yes"])

    def server_start(self) -> None:
        if shutil.which("lms"):
            _run(["lms", "server", "start"])

    # ---------- Inference ----------

    def complete_json(
        self,
        system: str,
        user: str,
        *,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
    ) -> dict[str, Any]:
        """Chat completion constrained to return a JSON object.

        LM Studio support for `response_format` varies per model. We try in order:
          1. response_format={"type":"json_object"} — OpenAI-style
          2. response_format={"type":"text"} — LM Studio accepts this form
          3. no response_format — plain text, recovered via `_extract_json`

        Whichever succeeds gets cached per-instance so subsequent calls skip retries.

        We also transparently recover from LM Studio auto-unloading the model
        mid-run (JIT eviction, idle timeout). On a 400 whose error text contains
        "Model unloaded" / "Invalid model identifier" we try `lms load <model>`
        once and retry the same call. Gives up after one reload attempt to
        avoid infinite loops when the model is genuinely gone.
        """
        model_id = model or self.model
        if not model_id:
            raise LMStudioError("No model specified (pass --model or set SECSCAN_MODEL).")

        base = {
            "model": model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        modes_to_try: list[dict | None]
        if self._json_mode is not None:
            modes_to_try = [self._json_mode]
        else:
            modes_to_try = [{"type": "json_object"}, {"type": "text"}, None]

        reload_attempted = False
        last_err: str = ""
        attempt = 0
        while attempt < 2:  # 0 = first try, 1 = retry after reload
            attempt += 1
            for mode in modes_to_try:
                payload = dict(base)
                if mode is not None:
                    payload["response_format"] = mode
                r = self._http.post("/chat/completions", json=payload)
                if r.status_code < 400:
                    self._json_mode = mode
                    # `r.json()` can raise `json.JSONDecodeError` directly when
                    # LM Studio returns a malformed/truncated HTTP body (seen
                    # mid-run on long sessions). That raw exception used to
                    # leak past every `except LMStudioError` in the codebase
                    # — killing whole arch/synth passes that should have just
                    # logged a per-call failure and continued. Wrap it so all
                    # response-side parse errors land in the same bucket
                    # `_extract_json` raises into.
                    try:
                        content = r.json()["choices"][0]["message"]["content"]
                    except (json.JSONDecodeError, LookupError, TypeError, ValueError) as e:
                        raise LMStudioError(
                            f"Malformed LM Studio response body "
                            f"(status {r.status_code}, mode={mode}): {e}"
                        ) from e
                    return _extract_json(content)
                last_err = f"{r.status_code}: {r.text[:300]}"
                if r.status_code != 400:
                    break
            if _is_model_unloaded(last_err) and not reload_attempted:
                reload_attempted = True
                if _try_reload_model(model_id):
                    continue  # retry the whole mode loop
            break

        hint = _ctx_overflow_hint(last_err, max_tokens)
        raise LMStudioError(f"LMStudio {last_err}{hint}")

    def complete_text(
        self,
        system: str,
        user: str,
        *,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> str:
        model_id = model or self.model
        if not model_id:
            raise LMStudioError("No model specified.")
        payload = {
            "model": model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        r = self._http.post("/chat/completions", json=payload)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


# ---------- helpers ----------

_MODEL_UNLOADED_KEYWORDS = (
    "model unloaded",
    "invalid model identifier",
    "model not found",
    "no model is loaded",
)


def _is_model_unloaded(err_text: str) -> bool:
    """True if the LM Studio error indicates the model is no longer available."""
    lo = err_text.lower()
    return any(k in lo for k in _MODEL_UNLOADED_KEYWORDS)


def _try_reload_model(model_id: str) -> bool:
    """Attempt to re-load a model via `lms load`. Returns True on success.

    Silently no-ops (returns False) when the `lms` CLI isn't installed — users
    running LM Studio headlessly without the CLI need to rely on the GUI's
    auto-reload or manual reload.
    """
    if not shutil.which("lms"):
        return False
    try:
        subprocess.run(
            ["lms", "load", model_id, "--yes"],
            check=True, capture_output=True, text=True, timeout=120,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


def _run(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return r.stdout
    except FileNotFoundError as e:
        raise LMStudioError(f"Command not found: {cmd[0]}") from e
    except subprocess.CalledProcessError as e:
        raise LMStudioError(f"{' '.join(cmd)} failed: {e.stderr.strip()}") from e


def _parse_lms_ls(output: str) -> list[ModelInfo]:
    """Best-effort parse of `lms ls` output. Shape varies by version."""
    models: list[ModelInfo] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(("LLM", "EMBEDDING", "PARAMS", "ARCHITECTURE", "—", "-")):
            continue
        # Rows look like: "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF    8B   llama    ✓"
        loaded = any(mark in line for mark in ("✓", "LOADED", "[loaded]"))
        ident = line.split()[0]
        if "/" in ident or ident.endswith(".gguf"):
            models.append(ModelInfo(identifier=ident, loaded=loaded))
    return models


def _ctx_overflow_hint(err: str, max_tokens: int) -> str:
    """Append an actionable hint when the LM Studio error looks like a context
    overflow. Many LM Studio errors for this case mention 'context' or
    'tokens'; if so, point the user at the likely fix."""
    low = err.lower()
    if any(kw in low for kw in ("context", "too many tokens", "exceeds", "max_position", "sequence length")):
        return (
            f" — likely context overflow (requested max_tokens={max_tokens}). "
            "Load the model in LM Studio with a larger --context-length (e.g. "
            "`lms load <model> -c 32768`) or pick a model with a larger window."
        )
    return ""


_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _extract_json(content: str) -> dict[str, Any]:
    """Parse JSON from a model's chat completion, with fallbacks for common
    LLM output glitches.

    Strategy, in order:
      1. Plain `json.loads` on the stripped content.
      2. Pull out a ```json fenced``` block if present.
      3. Slice the outermost {...} from the surrounding prose.
      4. Run the sliced text through `_repair_json` — strips comments,
         removes trailing commas, and iteratively asks `json.loads` where
         it choked, inserting commas at those positions. Recovers the
         classic 27B-class failure mode of dropping commas between
         sibling array elements or object fields.
    """
    content = content.strip()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    m = _JSON_BLOCK_RE.search(content)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            content = m.group(1)  # fall through to repair on the fenced payload

    # Slice outermost braces — drops <think>...</think> prefixes and stray suffixes
    start = content.find("{")
    end = content.rfind("}")
    if start < 0 or end <= start:
        raise LMStudioError(f"Could not parse JSON from model output: {content[:200]!r}")
    sliced = content[start : end + 1]

    try:
        return json.loads(sliced)
    except json.JSONDecodeError:
        pass

    repaired = _repair_json(sliced)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError as e:
        raise LMStudioError(
            f"Could not parse JSON after repair attempts (last error: {e}): "
            f"{sliced[:200]!r}"
        ) from e


def _repair_json(s: str, max_passes: int = 30) -> str:
    """Best-effort repair of LLM-emitted JSON.

    Cheap structural cleanups first (comments, trailing commas), then
    iteratively asks `json.loads` to point at the next failing position
    and applies a targeted fix there. Bounded by `max_passes` so a
    pathological input can't loop.
    """
    # 1. Strip JS-style comments models sometimes emit.
    s = _BLOCK_COMMENT_RE.sub("", s)
    s = _strip_line_comments_outside_strings(s)

    # 2. Remove trailing commas before } or ].
    s = _strip_trailing_commas(s)

    # 3. Iterative position-driven repair.
    for _ in range(max_passes):
        try:
            json.loads(s)
            return s
        except json.JSONDecodeError as e:
            fixed = _try_fix_at(s, e)
            if fixed is None or fixed == s:
                return s  # caller will surface the parse error
            s = fixed
    return s


def _try_fix_at(s: str, e: json.JSONDecodeError) -> str | None:
    """Apply a targeted edit at `e.pos` based on `e.msg`."""
    pos = e.pos
    msg = e.msg.lower()

    # Most common: missing comma between siblings. Parser is sitting at the
    # next token (`{`, `[`, `"`, or a literal) expecting a `,` first.
    if "expecting ',' delimiter" in msg or "expecting comma" in msg:
        return s[:pos] + "," + s[pos:]

    # Trailing comma: parser hit `}` or `]` after a comma and complains the
    # property name is missing. Walk back, drop the comma.
    if "expecting property name" in msg or "expecting value" in msg:
        i = pos - 1
        while i >= 0 and s[i].isspace():
            i -= 1
        if i >= 0 and s[i] == ",":
            return s[:i] + s[i + 1 :]

    return None


def _strip_trailing_commas(s: str) -> str:
    """Remove `,` immediately preceding `}` or `]`, ignoring commas inside strings."""
    out: list[str] = []
    in_string = False
    escape = False
    i = 0
    while i < len(s):
        c = s[i]
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == ",":
            # Look ahead past whitespace
            j = i + 1
            while j < len(s) and s[j].isspace():
                j += 1
            if j < len(s) and s[j] in "}]":
                # Drop this comma
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _strip_line_comments_outside_strings(s: str) -> str:
    """Remove `//...` comments that appear outside of string literals."""
    out: list[str] = []
    in_string = False
    escape = False
    i = 0
    while i < len(s):
        c = s[i]
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < len(s) and s[i + 1] == "/":
            # Skip to end of line
            j = s.find("\n", i)
            if j < 0:
                break
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)
