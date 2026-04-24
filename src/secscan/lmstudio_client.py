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
            timeout=httpx.Timeout(connect=5.0, read=600.0, write=30.0, pool=30.0),
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

        last_err: str = ""
        for mode in modes_to_try:
            payload = dict(base)
            if mode is not None:
                payload["response_format"] = mode
            r = self._http.post("/chat/completions", json=payload)
            if r.status_code < 400:
                # Cache the first mode that worked so we don't keep probing.
                self._json_mode = mode
                content = r.json()["choices"][0]["message"]["content"]
                return _extract_json(content)
            last_err = f"{r.status_code}: {r.text[:300]}"
            if r.status_code != 400:
                break
        raise LMStudioError(f"LMStudio {last_err}")

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


_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_json(content: str) -> dict[str, Any]:
    content = content.strip()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    m = _JSON_BLOCK_RE.search(content)
    if m:
        return json.loads(m.group(1))
    # Last resort: grab the outermost braces
    start = content.find("{")
    end = content.rfind("}")
    if start >= 0 and end > start:
        return json.loads(content[start : end + 1])
    raise LMStudioError(f"Could not parse JSON from model output: {content[:200]!r}")
