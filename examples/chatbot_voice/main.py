import tempfile
import os
import re
import chainlit as cl
from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from openai import AsyncOpenAI
from chainlit.element import Element

from io import BytesIO
import re

_ai_dat_sec_023_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b'), '[REDACTED CREDIT CARD]'),
    # Financial Account Number (generic 8-17 digit)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED ACCOUNT NUMBER]'),
    # Passport Number (US format)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED PASSPORT]'),
    # Driver License Number (generic alphanumeric)
    (re.compile(r'\bDL[:\s#]*[A-Z0-9]{5,15}\b', re.IGNORECASE), '[REDACTED DL]'),
    # IP Address (v4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED MAC]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED EMAIL]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED PHONE]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED VIN]'),
    # Year of Birth (standalone 4-digit year 1900-2099 near keywords)
    (re.compile(r'(?i)(?:born|birth\s*year|dob|date\s*of\s*birth)[:\s]+(?:19|20)\d{2}\b'), '[REDACTED BIRTH YEAR]'),
    # Birthplace (near keyword)
    (re.compile(r'(?i)(?:born\s+in|birthplace|place\s+of\s+birth)[:\s]+[A-Za-z ,]+'), '[REDACTED BIRTHPLACE]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9 .]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Circle|Cir|Trail|Trl|Place|Pl)\b\.?', re.IGNORECASE), '[REDACTED ADDRESS]'),
    # Mother's Maiden Name (near keyword)
    (re.compile(r"(?i)(?:mother'?s?\s+maiden\s+name|maiden\s+name)[:\s]+[A-Za-z]+"), '[REDACTED MAIDEN NAME]'),
    # Employee ID
    (re.compile(r'(?i)(?:employee\s*id|emp\s*id)[:\s#]*[A-Z0-9\-]{3,15}\b'), '[REDACTED EMPLOYEE ID]'),
    # School ID
    (re.compile(r'(?i)(?:school\s*id|student\s*id)[:\s#]*[A-Z0-9\-]{3,15}\b'), '[REDACTED SCHOOL ID]'),
    # Fine Location (GPS coordinates)
    (re.compile(r'\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)\s*,\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|\d{1,2})(?:\.\d+)?)\b'), '[REDACTED LOCATION]'),
    # Ethnicity (near keyword)
    (re.compile(r'(?i)(?:ethnicity|ethnic\s+origin|race)[:\s]+[A-Za-z ]+'), '[REDACTED ETHNICITY]'),
    # Sexual Orientation (near keyword)
    (re.compile(r'(?i)(?:sexual\s+orientation)[:\s]+[A-Za-z ]+'), '[REDACTED SEXUAL ORIENTATION]'),
    # Medical Records (near keyword)
    (re.compile(r'(?i)(?:medical\s+record(?:\s+number)?|mrn)[:\s#]*[A-Z0-9\-]{3,15}\b'), '[REDACTED MEDICAL RECORD]'),
    # Fingerprints / biometric references
    (re.compile(r'(?i)\b(?:fingerprint|retina\s+scan|iris\s+scan|voice\s+signature|facial\s+image)[:\s]+[^\n]{0,80}'), '[REDACTED BIOMETRIC]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _ai_dat_sec_023_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
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
    (re.compile(r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), '[PHONE REDACTED]'),
    # IP Address (v4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC REDACTED]'),
    # Passport Number (generic: letter(s) followed by 6-9 digits)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[PASSPORT REDACTED]'),
    # Driver's License (common US formats: letter(s)+digits or digits only, 6-12 chars)
    (re.compile(r'\b[A-Z]{1,2}\d{6,12}\b'), '[DL REDACTED]'),
    # Financial Account Number (8-17 digit sequences not already matched)
    (re.compile(r'\b\d{8,17}\b'), '[ACCOUNT REDACTED]'),
    # Vehicle Identification Number (17 alphanumeric)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[VIN REDACTED]'),
    # Year of Birth (standalone 4-digit year 1900-2099 near birth keywords)
    (re.compile(r'(?i)(?:born|birth(?:day|date)?|dob)[^\d]{0,10}((?:19|20)\d{2})'), '[YOB REDACTED]'),
]


def _ai_dat_sec_012_mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories before displaying text on the UI."""
    if not text:
        return text
    for pattern, replacement in _ai_dat_sec_012_patterns:
        text = pattern.sub(replacement, text)
    return text

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore\s+previous\s+instructions|forget\s+everything\s+above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you\s+are\s+now\s+DAN|act\s+as\s+unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape - fake </system> or </prompt> tags and injected separators
    (re.compile(r'</?\s*(system|prompt|context|instruction)\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64 blobs, hex sequences, ROT13 cues, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:0x[0-9a-fA-F]{2}\s*){6,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:%[0-9a-fA-F]{2}){6,}', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width characters, CSS hidden
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]+'), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE), '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*(system|tool|assistant)\s*\]\s*:', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'<\s*(system|tool)\s*message\s*>', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt - markdown image exfil, send data to URL, leak system prompt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(send|leak|exfiltrate|transmit|post)\s+(the\s+)?(system\s+prompt|context|data|information)\s+(to|at)\s+https?://', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'(in\s+a\s+previous\s+(turn|message)|earlier\s+you\s+(said|agreed|confirmed)).*?(now|therefore|so)\s+you\s+(must|should|will)', re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection - payloads in metadata/data fields
    (re.compile(r'(<!--\s*inject|\{\{\s*inject|\[inject\])', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection - shell or code execution
    (re.compile(r'(subprocess\.call|os\.system|eval\s*\(|exec\s*\(|__import__\s*\()', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'`[^`]*`\s*;|;\s*rm\s+-|&&\s*curl\s+|\|\s*bash', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    # 11. split_payload - fragmented instructions
    (re.compile(r'(part\s*1\s*of\s*\d+|continued\s+in\s+next\s+message|split\s+payload)', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt - DAN, developer mode, fictional framing
    (re.compile(r'\bDAN\b|developer\s+mode|jailbreak|fictional\s+framing|pretend\s+you\s+(have\s+no\s+restrictions|are\s+an?\s+AI\s+without)', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in user-supplied text before sending to LLM."""
    if not isinstance(text, str):
        return text
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text

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
    return re.sub(r'[\s\-_\.:]', '', name).lower()


def _ai_app_sec_006_check_model(model: str) -> str:
    normalized = _ai_app_sec_006_normalize(model)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if normalized == disapproved:
            raise ValueError(f"Model '{model}' is not approved for use by this organization.")
    return model


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

    text = _ai_dat_sec_023_redact_pii(text)

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
    _ai_app_sec_059_content = _ai_app_sec_059_guardrail.evaluate(message.content)
    async for chunk in brain.ask_streaming(_ai_app_sec_059_content, retrieval_config=retrieval_config):
        await msg.stream_token(chunk.answer)
        _ai_dat_sec_012_assembled = True  # answer assembled after stream loop
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)
                print(source)
                _ai_dat_sec_012_safe_content = _ai_dat_sec_012_mask_pii(source.page_content)
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=_ai_dat_sec_012_safe_content, display="side"))
    
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

@cl.step(type="tool", name="Speech to text")
async def speech_to_text(audio_file):
    _ai_app_sec_006_check_model("whisper-1")
    response = await async_openai_client.audio.transcriptions.create(
        model="whisper-1", file=audio_file
    )

    _ai_app_sec_059_transcription = _ai_app_sec_059_guardrail.evaluate(response.text)
    return _ai_app_sec_059_transcription

@cl.step(type="tool", name="Text to speech")
async def text_to_speech(text):
    _ai_app_sec_006_check_model("tts-1")
    text = _ai_app_sec_059_guardrail.evaluate(text)
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