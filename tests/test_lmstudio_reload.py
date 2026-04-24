from secscan.lmstudio_client import _is_model_unloaded


def test_detects_model_unloaded():
    cases_should_match = [
        '400: {"error":"Model unloaded."}',
        '400: {"error":{"message":"Invalid model identifier \\"qwen-32k\\". …"}}',
        "Model not found",
        "500: {\"error\": \"No model is loaded\"}",
    ]
    for c in cases_should_match:
        assert _is_model_unloaded(c), f"should detect unloaded: {c}"

    cases_should_not_match = [
        "Context size has been exceeded.",
        "429 rate limited",
        "unrelated error message",
    ]
    for c in cases_should_not_match:
        assert not _is_model_unloaded(c), f"should NOT detect unloaded: {c}"
