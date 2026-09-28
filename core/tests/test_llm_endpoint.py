import os
import re


def _ai_app_sec_006_check_model(model: str) -> str:
    """Raise ValueError if model is on the organization's disapproved list."""
    _ai_app_sec_006_disapproved = [
        "deepseekchat",
        "deepseekr1",
        "deepseekr1distillllama70b",
        "deepseekreasoner",
        "customllmclientnull",
        "deepseekchatnull",
        "openrouternull",
        "usdeepseekr1v10null",
    ]
    normalized = re.sub(r"[\s\-_\.:\u0000]", "", model).lower()
    if normalized in _ai_app_sec_006_disapproved:
        raise ValueError(
            f"Model '{model}' is on the organization's disapproved list and cannot be used."
        )
    return model


import pytest
from langchain_core.language_models import FakeListChatModel
from pydantic import ValidationError
from quivr_core.rag.entities.config import LLMEndpointConfig
from quivr_core.llm import LLMEndpoint


@pytest.mark.base
def test_llm_endpoint_from_config_default():
    from langchain_openai import ChatOpenAI

    del os.environ["OPENAI_API_KEY"]

    with pytest.raises((ValidationError, ValueError)):
        llm = LLMEndpoint.from_config(LLMEndpointConfig())

    # Working default
    _ai_app_sec_006_check_model("gpt-4o-mini")
    config = LLMEndpointConfig(llm_api_key="test")
    llm = LLMEndpoint.from_config(config=config)

    assert llm.supports_func_calling()
    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name in llm.get_config().model


@pytest.mark.base
def test_llm_endpoint_from_config():
    from langchain_openai import ChatOpenAI

    _ai_app_sec_006_check_model("llama2")
    config = LLMEndpointConfig(
        model="llama2", llm_api_key="test", llm_base_url="http://localhost:8441"
    )
    llm = LLMEndpoint.from_config(config)

    assert not llm.supports_func_calling()
    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name in llm.get_config().model


def test_llm_endpoint_constructor():
    llm_endpoint = FakeListChatModel(responses=[])
    _ai_app_sec_006_check_model("test")
    llm_endpoint = LLMEndpoint(
        llm=llm_endpoint, llm_config=LLMEndpointConfig(model="test")
    )

    assert not llm_endpoint.supports_func_calling()
