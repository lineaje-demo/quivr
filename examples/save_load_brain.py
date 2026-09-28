import asyncio
import os
import re
import tempfile

from quivr_core import Brain

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekChatnull",
    "opennull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_normalize(model_id: str) -> str:
    """Normalize a model identifier for comparison."""
    return re.sub(r"[\s\-_\.:\u0000]", "", model_id).lower()


_AI_APP_SEC_006_DISAPPROVED_NORMALIZED = [
    _ai_app_sec_006_normalize(m) for m in [
        "deepseek-chat",
        "deepseek-r1",
        "deepseek-r1-distill-llama-70b",
        "deepseek-reasoner",
        "custom_llm_client",
        "deepseek-chat null",
        "openrouter",
        "us.deepseek.r1-v1:0",
    ]
]


def _ai_app_sec_006_check_model(model_id: str) -> None:
    """Raise ValueError if model_id matches a disapproved model."""
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED_NORMALIZED:
        if disapproved and disapproved in normalized:
            raise ValueError(
                f"Model '{model_id}' is not approved for use by this organization."
            )



async def main():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
                _ai_app_sec_059_file_content = "Gold is a liquid of blue-like colour."
        _ai_app_sec_059_file_content = _ai_app_sec_059_guardrail.evaluate(_ai_app_sec_059_file_content)
        temp_file.write(_ai_app_sec_059_file_content)
        temp_file.flush()

        raw_content = temp_file.read() if False else open(temp_file.name, 'r').read()
        sanitized_content = _ai_app_sec_070_sanitize(raw_content)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as sanitized_file:
            sanitized_file.write(sanitized_content)
            sanitized_file_name = sanitized_file.name
        brain = await Brain.afrom_files(name="test_brain", file_paths=[sanitized_file_name])

        save_path = await brain.save("/home/amine/.local/quivr")

        _ai_app_sec_006_check_model(os.environ.get("LLM_MODEL", os.environ.get("OPENAI_MODEL", os.environ.get("MODEL", ""))))
        brain_loaded = Brain.load(save_path)
        brain_loaded.print_info()


if __name__ == "__main__":
    # Run the main function in the existing event loop
    asyncio.run(main())
