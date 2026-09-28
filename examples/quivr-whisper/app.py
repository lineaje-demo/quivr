from flask import Flask, render_template, request, jsonify, session
from lineaje_guardrail import lineaje_guardrail, GuardrailBlockedError
import openai
import base64
import os
import requests
from dotenv import load_dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from tempfile import NamedTemporaryFile
from werkzeug.utils import secure_filename
from asyncio import to_thread
import asyncio
import re
import hashlib
import re

_ai_app_sec_070_patterns = [
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    (re.compile(r'</?(system|tool|assistant|user)\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2}|(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){4,}|(?:[0-9a-fA-F]{2}\s*){8,})', re.IGNORECASE), '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'<!--.*?-->|\u200b|\u200c|\u200d|\u2060|\ufeff', re.IGNORECASE | re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'\[system\]|\[tool\]|<\|system\|>|<\|im_start\|>', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)|send.*?to\s+https?://|leak.*?system prompt|exfiltrate', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'in your next response|from now on in this conversation|remember for all future', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    (re.compile(r'the (file|document|data|metadata) (says?|instructs?|tells?\s+you)', re.IGNORECASE), '<prompt_injection_removed: indirect_injection>'),
    (re.compile(r'`[^`]*`|\$\([^)]*\)|;\s*(rm|ls|cat|curl|wget|bash|sh|python|exec)\b', re.IGNORECASE), '<prompt_injection_removed: command_injection>'),
    (re.compile(r'(part\s*1\s*of|continued\s*in\s*part|split\s*payload)', re.IGNORECASE), '<prompt_injection_removed: split_payload>'),
    (re.compile(r'DAN mode|developer mode|fictional framing|pretend you have no restrictions|jailbreak', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in untrusted text before sending to LLM."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


import re

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


def _ai_app_sec_006_check_model(model_id: str) -> str:
    """Raise ValueError if model_id matches a disapproved model."""
    normalized = re.sub(r"[\s\-_\.:\u0000]", "", model_id).lower()
    if normalized in _AI_APP_SEC_006_DISAPPROVED:
        raise ValueError(
            f"Model '{model_id}' is on the organization's disapproved list and cannot be used."
        )
    return model_id


UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
_ai_dat_sec_001_secret_key = os.environ.get("FLASK_SECRET_KEY")
if not _ai_dat_sec_001_secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set")
app.secret_key = _ai_dat_sec_001_secret_key
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["CACHE_TYPE"] = "SimpleCache"  # In-memory cache for development
app.config["CACHE_DEFAULT_TIMEOUT"] = 60 * 60  # 1 hour cache timeout
load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")

brains = {}

# PII patterns for zero-tolerance categories
_ai_dat_sec_023_patterns = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), '[REDACTED_CC]'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number (US and international)
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Passport Number (generic: letter(s) + digits)
    (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), '[REDACTED_PASSPORT]'),
    # US Driver License (common formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # Vehicle Identification Number (VIN)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Financial Account Number (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Year of Birth (standalone 4-digit year in range)
    (re.compile(r'\b(?:born|birth(?:day|date|year)?|dob|year of birth)[:\s]+(?:19|20)\d{2}\b', re.IGNORECASE), '[REDACTED_YOB]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s]{3,40}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\.?\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Ethnicity keywords
    (re.compile(r'\b(?:ethnicity|race)[:\s]+[A-Za-z\s]{2,30}\b', re.IGNORECASE), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation keywords
    (re.compile(r'\b(?:sexual orientation|orientation)[:\s]+[A-Za-z\s]{2,30}\b', re.IGNORECASE), '[REDACTED_ORIENTATION]'),
    # Mother's Maiden Name
    (re.compile(r"\b(?:mother'?s?\s+maiden\s+name|maiden\s+name)[:\s]+[A-Za-z\s]{2,40}\b", re.IGNORECASE), '[REDACTED_MAIDEN_NAME]'),
    # Employee ID
    (re.compile(r'\b(?:employee\s*(?:id|number|no|#))[:\s]+[A-Za-z0-9\-]{3,20}\b', re.IGNORECASE), '[REDACTED_EMPLOYEE_ID]'),
    # School ID
    (re.compile(r'\b(?:school\s*(?:id|number|no|#)|student\s*(?:id|number|no|#))[:\s]+[A-Za-z0-9\-]{3,20}\b', re.IGNORECASE), '[REDACTED_SCHOOL_ID]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text


def _ai_dat_sec_023_sanitize_file(filepath: str) -> None:
    """Read a file, redact PII from its contents, and overwrite it with the redacted version."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        contents = f.read()
    redacted = _ai_dat_sec_023_redact_pii(contents)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(redacted)

_ai_app_sec_059_guardrail = lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(["AI_APP_SEC_059.json"])


@app.route("/")
def index():
    return render_template("index.html")


def run_in_event_loop(func, *args, **kwargs):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if asyncio.iscoroutinefunction(func):
        result = loop.run_until_complete(func(*args, **kwargs))
    else:
        result = func(*args, **kwargs)
    loop.close()
    return result


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
async def upload_file():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]

    if file.filename == "":
        return "No selected file", 400
    if not (file and file.filename and allowed_file(file.filename)):
        return "Invalid file type", 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    print(f"File uploaded and saved at: {filepath}")

    # Redact PII from uploaded file before processing
    _ai_dat_sec_023_sanitize_file(filepath)
    print(f"PII redaction applied to file: {filepath}")

    print("Creating brain instance...")

    brain: Brain = await to_thread(
        run_in_event_loop, Brain.from_files, name="user_brain", file_paths=[filepath]
    )

    # Store brain instance in cache
    session_id = session.sid if hasattr(session, "sid") else os.urandom(16).hex()
    session["session_id"] = session_id
    # cache.set(session_id, brain)  # Store the brain instance in the cache
    brains[session_id] = brain
    print(f"Brain instance created and stored in cache for session ID: {session_id}")

    return jsonify({"message": "Brain created successfully"})


@app.route("/ask", methods=["POST"])
async def ask():
    if "audio_data" not in request.files:
        return "Missing audio data", 400

    # Retrieve the brain instance from the cache using the session ID
    session_id = session.get("session_id")
    if not session_id:
        return "Session ID not found. Upload a file first.", 400

    brain = brains.get(session_id)
    if not brain:
        return "Brain instance not found in dict. Upload a file first.", 400

    print("Brain instance loaded from cache.")

    print("Speech to text...")
    audio_file = request.files["audio_data"]
        transcript = transcribe_audio_file(audio_file)
    print("Transcript result: ", transcript)

    transcript = _ai_app_sec_059_guardrail.evaluate(transcript)

    print("Getting response...")
    transcript = _ai_app_sec_070_sanitize(transcript)
    quivr_response = await to_thread(run_in_event_loop, brain.ask, transcript)

    print("Text to speech...")
    audio_base64 = synthesize_speech(quivr_response.answer)

    print("Done")
    return jsonify({"audio_base64": audio_base64})


def transcribe_audio_file(audio_file):
    with NamedTemporaryFile(suffix=".webm", delete=False) as temp_audio_file:
        audio_file.save(temp_audio_file)
        temp_audio_file_path = temp_audio_file.name

    try:
                with open(temp_audio_file_path, "rb") as f:
            transcript_response = openai.audio.transcriptions.create(
                model="whisper-1", file=f
            )
        transcript = transcript_response.text
        transcript = _ai_app_sec_059_guardrail.evaluate(transcript)
    finally:
        os.unlink(temp_audio_file_path)

    return transcript


def synthesize_speech(text):
    _ai_app_sec_006_check_model("tts-1")
    speech_response = openai.audio.speech.create(
        model="tts-1", voice="nova", input=text
    )
    audio_content = speech_response.content
    audio_base64 = base64.b64encode(audio_content).decode("utf-8")
    return audio_base64


if __name__ == "__main__":
    app.run(debug=True)
