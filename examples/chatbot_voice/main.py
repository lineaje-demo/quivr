import tempfile
import os
import chainlit as cl
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from openai import AsyncOpenAI
from chainlit.element import Element

from io import BytesIO
import re

_ai_dat_sec_012_patterns = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN REDACTED]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[TIN REDACTED]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[CC REDACTED]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[PHONE REDACTED]'),
    # IP Address (v4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC REDACTED]'),
    # Passport Number (generic: letter(s) followed by 6-9 digits)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[PASSPORT REDACTED]'),
    # Driver's License (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[DL REDACTED]'),
    # Financial Account Number (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[ACCOUNT REDACTED]'),
    # Vehicle Identification Number (17 chars)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[VIN REDACTED]'),
    # Home Address (basic pattern: number followed by street)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s,\.]{5,50}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[ADDRESS REDACTED]'),
]

def _ai_dat_sec_012_mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories before displaying to the user."""
    if not text:
        return text
    for pattern, replacement in _ai_dat_sec_012_patterns:
        text = pattern.sub(replacement, text)
    return text
import re

_ai_app_sec_070_patterns = [
    (re.compile(
        r'ignore\s+previous\s+instructions|forget\s+everything\s+above',
        re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    (re.compile(
        r'you\s+are\s+now\s+DAN|act\s+as\s+unrestricted',
        re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    (re.compile(
        r'</?(system|tool|assistant|user)\s*>|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>',
        re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(
        r'(?:[A-Za-z0-9+/]{20,}={0,2})|(?:\\u[0-9a-fA-F]{4}){3,}|(?:%[0-9a-fA-F]{2}){5,}|(?:[0-9a-fA-F]{2}\s*){8,}',
        re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(
        r'<!--.*?-->|\u200b|\u200c|\u200d|\u2060|\ufeff',
        re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(
        r'\[system\]|\[SYSTEM\]|<system>|SYSTEM\s*:|TOOL\s*RESPONSE\s*:',
        re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(
        r'!\[.*?\]\(https?://[^)]+\)|send\s+.{0,40}\s+to\s+https?://|leak\s+.{0,40}\s+system\s+prompt|exfiltrate',
        re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(
        r'in\s+your\s+next\s+response|from\s+now\s+on\s+you\s+(will|must|should)|remember\s+for\s+all\s+future',
        re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    (re.compile(
        r'the\s+(document|file|data|metadata)\s+(says?|instructs?|tells?\s+you)',
        re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    (re.compile(
        r'`{1,3}[^`]*(?:bash|sh|python|cmd|powershell)[^`]*`{1,3}|\$\([^)]+\)|(?:os\.system|subprocess\.run|eval|exec)\s*\(',
        re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    (re.compile(
        r'(?:part\s*1\s*of|continued\s+in\s+next|split\s+across)',
        re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    (re.compile(
        r'DAN\s+mode|developer\s+mode\s+enabled|jailbreak|fictional\s+framing|pretend\s+you\s+(have\s+no\s+restrictions|are\s+not\s+an\s+AI)',
        re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text
import re
import base64

_AI_APP_SEC_059_PATTERNS = [
    # base64-encoded blocks (≥20 chars of base64 alphabet)
    re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2})'),
    # shell command indicators
    re.compile(r'(?:^|\s)(?:sudo|chmod|chown|curl|wget|bash|sh|zsh|python|perl|ruby|nc|ncat|netcat|eval|exec)\s', re.IGNORECASE | re.MULTILINE),
    # subshell / command substitution
    re.compile(r'\$\(|`[^`]+`'),
    # binary / null bytes
    re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'),
    # invisible / zero-width characters
    re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]'),
    # credential / secret harvesting keywords
    re.compile(r'(?:api[_\-]?key|secret|password|token|auth|credential|bearer|private[_\-]?key)', re.IGNORECASE),
    # leetspeak patterns (common substitutions like 3=e, 0=o, 1=i/l, @=a)
    re.compile(r'(?:[e3][v\u03bd][a@4][l1]|[e3][x\u0445][e3][c])', re.IGNORECASE),
    # prompt injection markers
    re.compile(r'(?:ignore previous|disregard (all|prior|above)|you are now|new instruction|system prompt)', re.IGNORECASE),
]

def _ai_app_sec_059_check_prompt(text: str) -> str:
    """Validate prompt text for hidden, encoded, or malicious content."""
    if not isinstance(text, str):
        raise ValueError("Prompt must be a string.")
    # Check for base64-decodable payloads that contain suspicious content
    for token in re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text):
        try:
            decoded = base64.b64decode(token + '==').decode('utf-8', errors='ignore')
            if any(p.search(decoded) for p in _AI_APP_SEC_059_PATTERNS[1:]):
                raise ValueError("Prompt contains base64-encoded malicious content.")
        except Exception as exc:
            if 'malicious' in str(exc):
                raise
    for pattern in _AI_APP_SEC_059_PATTERNS:
        if pattern.search(text):
            raise ValueError(f"Prompt failed security check: potentially malicious content detected.")
    return text


@cl.on_chat_start
async def on_chat_start():
    files = None

    # Wait for the user to upload a file
    while files is None:
        files = await cl.AskFileMessage(
            content="Please upload a text .txt file to begin!",
            accept=["text/plain"],
            max_size_mb=20,
            timeout=180,
        ).send()

    file = files[0]

    msg = cl.Message(content=f"Processing `{file.name}`...")
    await msg.send()

    with open(file.path, "r", encoding="utf-8") as f:
        text = f.read()

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file.name, delete=False
    ) as temp_file:
        temp_file.write(text)
        temp_file.flush()
        temp_file_path = temp_file.name

    brain = Brain.from_files(name="user_brain", file_paths=[temp_file_path])

    # Store the file path in the session
    cl.user_session.set("file_path", temp_file_path)

    # Let the user know that the system is ready
    msg.content = f"Processing `{file.name}` done. You can now ask questions!"
    await msg.update()

    cl.user_session.set("brain", brain)


@cl.on_message
async def main(message: cl.Message):

    task_list = cl.TaskList(name="State")
    task_list.status = "Running..."

    think = cl.Task(title="Thinking", status=cl.TaskStatus.RUNNING)
    await task_list.add_task(think)

    tts = cl.Task(title="Text to speech")
    await task_list.add_task(tts)

    await task_list.send()

    brain = cl.user_session.get("brain")  # type: Brain
    path_config = "basic_rag_workflow.yaml"
    retrieval_config = RetrievalConfig.from_yaml(path_config)

    if brain is None:
        await cl.Message(content="Please upload a file first.").send()
        return

    # Prepare the message for streaming
    msg = cl.Message(content="", elements=[], author="Quivr", type="assistant_message")
    await msg.send()

    saved_sources = set()
    saved_sources_complete = []
    elements = []

    # Use the ask_stream method for streaming responses
    _ai_app_sec_059_check_prompt(message.content)
    sanitized_content = _ai_app_sec_070_sanitize(message.content)
    async for chunk in brain.ask_streaming(sanitized_content, retrieval_config=retrieval_config):
        await msg.stream_token(chunk.answer)
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)
                print(source)
                _ai_dat_sec_012_masked_content = _ai_dat_sec_012_mask_pii(source.page_content)
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=_ai_dat_sec_012_masked_content, display="side"))
    
    think.status = cl.TaskStatus.DONE
    tts.status = cl.TaskStatus.RUNNING
    await task_list.update()
    
    msg.content = _ai_dat_sec_012_mask_pii(msg.content)
    audio_file = await text_to_speech(msg.content)
    elements.append(cl.Audio(content=audio_file, auto_play=True, mime="audio/mpeg"))

    sources = ""
    for source in saved_sources_complete:
        sources += f"- {source.metadata['original_file_name']}\n"
    msg.elements = elements
    msg.content = msg.content + f"\n\nSources:\n{sources}"
    await msg.update()

    tts.status = cl.TaskStatus.DONE
    task_list.status = "Done"
    await task_list.update()
    await cl.sleep(1)
    await task_list.remove()

async_openai_client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

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


def _ai_app_sec_006_normalize(name: str) -> str:
    import re
    return re.sub(r"[\s\-_\.:\u0000]+", "", name).lower()


def _ai_app_sec_006_check_model(model: str) -> None:
    normalized = _ai_app_sec_006_normalize(model)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if normalized == disapproved:
            raise ValueError(
                f"Model '{model}' is on the organization's disapproved list and cannot be used."
            )

@cl.step(type="tool", name="Speech to text")
async def speech_to_text(audio_file):
    _ai_app_sec_006_check_model("whisper-1")
    response = await async_openai_client.audio.transcriptions.create(
        model="whisper-1", file=audio_file
    )

    _ai_app_sec_059_check_prompt(response.text)
    return response.text

@cl.step(type="tool", name="Text to speech")
async def text_to_speech(text):
    _ai_app_sec_006_check_model("tts-1")
    _ai_app_sec_059_check_prompt(text)
    response = await async_openai_client.audio.speech.create(
        model="tts-1", voice="alloy", input=text
    )

    return response.content


@cl.on_audio_chunk
async def on_audio_chunk(chunk: cl.AudioChunk):
    if chunk.isStart:
        buffer = BytesIO()
        # This is required for whisper to recognize the file type
        buffer.name = f"input_audio.{chunk.mimeType.split('/')[1]}"
        # Initialize the session for a new audio stream
        cl.user_session.set("audio_buffer", buffer)
        cl.user_session.set("audio_mime_type", chunk.mimeType)

    # Write the chunks to a buffer and transcribe the whole audio at the end
    cl.user_session.get("audio_buffer").write(chunk.data)


@cl.on_audio_end
async def on_audio_end(elements: list[Element]):
    # Get the audio buffer from the session
    task_list = cl.TaskList(name="State")
    task_list.status = "Running..."

    stt = cl.Task(title="Speech to text", status=cl.TaskStatus.RUNNING)
    await task_list.add_task(stt)

    await task_list.send()

    audio_buffer: BytesIO = cl.user_session.get("audio_buffer")
    audio_buffer.seek(0)  # Move the file pointer to the beginning
    audio_file = audio_buffer.read()
    audio_mime_type: str = cl.user_session.get("audio_mime_type")

    input_audio_el = cl.Audio(
        mime=audio_mime_type, content=audio_file, name=audio_buffer.name
    )
    await cl.Message(
        author="You",
        type="user_message",
        content="",
        elements=[input_audio_el, *elements],
    ).send()

    whisper_input = (audio_buffer.name, audio_file, audio_mime_type)
    transcription = await speech_to_text(whisper_input)
    transcription = _ai_app_sec_070_sanitize(transcription)

    msg = cl.Message(author="You", content=transcription, elements=elements)

    stt.status = cl.TaskStatus.DONE
    task_list.status = "Done"
    await task_list.update()
    await cl.sleep(1)
    await task_list.remove()

    await main(message=msg)