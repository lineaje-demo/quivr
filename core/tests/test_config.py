import re
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig

_AI_APP_SEC_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_check_model(model: str) -> str:
    """Raise ValueError if model is on the organisation's disapproved list."""
    normalised = re.sub(r"[\s\-_\.:\u0000]", "", model).lower()
    if normalised in _AI_APP_SEC_006_DISAPPROVED:
        raise ValueError(
            f"Model '{model}' is on the organisation's disapproved list and may not be used."
        )
    return model


def test_default_llm_config():
    config = LLMEndpointConfig()

    assert (
        config.model_dump()
        == LLMEndpointConfig(
            model=_ai_app_sec_006_check_model("gpt-4o"),
            llm_base_url=None,
            llm_api_key=None,
            max_context_tokens=2000,
            max_output_tokens=2000,
            temperature=0.7,
            streaming=True,
        ).model_dump()
    )


def test_default_retrievalconfig():
    config = RetrievalConfig()

    assert config.max_files == 20
    assert config.prompt is None
    print("\n\n", config.llm_config, "\n\n")
    print("\n\n", LLMEndpointConfig(), "\n\n")
    assert config.llm_config == LLMEndpointConfig()
