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


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for comparison."""
    return re.sub(r'[\s\-_\.:]', '', name).lower()


_AI_APP_SEC_006_DISAPPROVED_MODELS = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


class MegaparseConfig(MegaparseBaseConfig):
    method: ParserType = ParserType.UNSTRUCTURED
    strategy: StrategyEnum = StrategyEnum.FAST
    check_table: bool = False
    parsing_instruction: str | None = None
    model_name: str = "gpt-4o"

    @field_validator("model_name")
    @classmethod
    def _ai_app_sec_006_check_model(cls, v: str) -> str:
        normalized = _ai_app_sec_006_normalize(v)
        for disapproved in _AI_APP_SEC_006_DISAPPROVED_MODELS:
            if normalized == disapproved or normalized.startswith(disapproved.rstrip('null')):
                raise ValueError(
                    f"Model '{v}' is disapproved by the organization's model registry."
                )
        return v
