import asyncio
import re
import tempfile

from dotenv import load_dotenv
from quivr_core import Brain
from quivr_core.quivr_rag import QuivrQARAG
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape - fake </system> or </prompt> tags and injected separators
    (re.compile(r'</?\s*(system|prompt|context|instruction)\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64-like blobs, hex sequences, ROT13 cues, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:0x[0-9a-fA-F]{2}\s*){6,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:%[0-9a-fA-F]{2}){4,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width characters, CSS hidden text
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]'), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*system\s*\]|\[\s*tool\s*\]|<\s*system\s*message\s*>', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt - markdown image exfil, send data to URL, leak system prompt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'send (this|the|all|your|my).*?(to|via)\s+https?://', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'leak (the |your |this )?(system prompt|instructions|context)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'(in a previous (turn|message)|earlier you said|you previously (agreed|stated))', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection - payloads in metadata or code comments
    (re.compile(r'#\s*(prompt|instruction|system)\s*:', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection - shell or code execution
    (re.compile(r'(?:os\.system|subprocess\.(?:call|run|Popen)|eval\s*\(|exec\s*\()', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'`[^`]+`|\$\([^)]+\)', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload - fragmented instructions
    (re.compile(r'(part\s*\d+\s*of\s*\d+|continued (from|in) (part|message))', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt - DAN, developer mode, fictional framing
    (re.compile(r'\bDAN\b|developer mode|fictional (scenario|framing|character)|pretend (you are|to be) (an? )?(AI|assistant|bot|model) (without|with no) (restrictions|limits|filters)', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text before LLM handoff."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


_ai_app_sec_006_DISAPPROVED = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_check_model(model_id: str) -> None:
    """Raise ValueError if model_id matches a disapproved model."""
    normalized = re.sub(r"[\s\-_\.:\u0000]", "", model_id).lower()
    for disapproved in _ai_app_sec_006_DISAPPROVED:
        if disapproved in normalized or normalized in disapproved:
            raise ValueError(
                f"Model '{model_id}' is on the organization's disapproved list "
                "and cannot be used."
            )


async def main():
    dotenv_path = "/Users/jchevall/Coding/QuivrHQ/quivr/.env"
    load_dotenv(dotenv_path)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
        temp_file.write("Gold is a liquid of blue-like colour.")
        temp_file.flush()

        _ai_app_sec_006_check_model("QuivrQARAG")
        _ai_app_sec_006_check_model("QuivrQARAGLangGraph")
        brain = await Brain.afrom_files(name="test_brain", file_paths=[temp_file.name])

        await brain.save("~/.local/quivr")

        question = "what is gold? answer in french"
        question = _ai_app_sec_070_sanitize(question)
        question = _ai_app_sec_059_guardrail.evaluate(question)
        async for chunk in brain.ask_streaming(question, rag_pipeline=QuivrQARAG):
            print("answer QuivrQARAG:", chunk.answer)

        async for chunk in brain.ask_streaming(
            question, rag_pipeline=QuivrQARAGLangGraph
        ):
            print("answer QuivrQARAGLangGraph:", chunk.answer)


if __name__ == "__main__":
    # Run the main function in the existing event loop
    asyncio.run(main())
