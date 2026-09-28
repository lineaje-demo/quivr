import re
from enum import Enum

import yaml
from pydantic import BaseModel, field_validator


class ParserType(str, Enum):
    """Parser type enumeration."""

    UNSTRUCTURED = "unstructured"
    LLAMA_PARSER = "llama_parser"
    MEGAPARSE_VISION = "megaparse_vision"


class StrategyEnum(str, Enum):
    """Method to use for the conversion"""

    FAST = "fast"
    AUTO = "auto"
    HI_RES = "hi_res"


class MegaparseBaseConfig(BaseModel):
    @classmethod
    def from_yaml(cls, file_path: str):
        # Load the YAML file
        with open(file_path, "r") as stream:
            config_data = yaml.safe_load(stream)

        # Instantiate the class using the YAML data
        return cls(**config_data)


_ai_app_sec_006_DISAPPROVED_PATTERNS = [
    "deepseek",
    "customllmclient",
    "openrouter",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for registry comparison."""
    return re.sub(r"[\s\-_\.:\u0000-\u001f]", "", name).lower()


def _ai_app_sec_006_check_model(model_name: str) -> str:
    """Raise ValueError if model_name matches a disapproved model."""
    normalized = _ai_app_sec_006_normalize(model_name)
    for pattern in _ai_app_sec_006_DISAPPROVED_PATTERNS:
        if pattern in normalized:
            raise ValueError(
                f"Model '{model_name}' is not approved for use by this organization."
            )
    return model_name


class MegaparseConfig(MegaparseBaseConfig):
    method: ParserType = ParserType.UNSTRUCTURED
    strategy: StrategyEnum = StrategyEnum.FAST
    check_table: bool = False
    parsing_instruction: str | None = None
    model_name: str = "gpt-4o"

    @field_validator("model_name")
    @classmethod
    def _ai_app_sec_006_validate_model_name(cls, v: str) -> str:
        return _ai_app_sec_006_check_model(v)
