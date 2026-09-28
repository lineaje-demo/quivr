from flask import Flask, render_template, request, jsonify, session
import re
import openai
import base64
import os
import re
import requests
from dotenv import load_dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from tempfile import NamedTemporaryFile
from werkzeug.utils import secure_filename
from asyncio import to_thread
import asyncio
import re


_AI_APP_SEC_059_PATTERNS = [
    # Base64-encoded blocks (long runs of base64 chars)
    re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})'),
    # Shell command indicators
    re.compile(r'(?:^|\s)(?:sudo|bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\-]', re.IGNORECASE | re.MULTILINE),
    # Binary/null bytes
    re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]'),
    # Credential/secret seeking
    re.compile(r'(?:api[_\s-]?key|secret|password|token|auth|credential|bearer|private[_\s-]?key)', re.IGNORECASE),
    # Invisible/zero-width characters
    re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]'),
    # Leetspeak patterns (common substitutions suggesting obfuscation)
    re.compile(r'(?:[3][xX][3][cC]|[3][vV][4][lL]|[5][hH][3][lL][lL]|[0][sS][yY][sS])', re.IGNORECASE),
    # Prompt injection keywords
    re.compile(r'(?:ignore\s+(?:previous|above|prior)|disregard\s+(?:previous|above|prior)|you\s+are\s+now|new\s+instructions?|system\s*:\s*you)', re.IGNORECASE),
]


def _ai_app_sec_059_check_prompt(text: str) -> str:
    """Check prompt text for hidden, encoded, or malicious content.

    Raises ValueError if suspicious content is detected.
    Returns the original text if it passes all checks.
    """
    if not isinstance(text, str):
        raise ValueError("Prompt must be a string.")
    for pattern in _AI_APP_SEC_059_PATTERNS:
        match = pattern.search(text)
        if match:
            raise ValueError(
                f"Prompt rejected: suspicious content detected matching pattern '{pattern.pattern}' "
                f"at position {match.start()}."
            )
    return text


UPLOAD_FOLDER = "uploads"

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
    return re.sub(r"[\s\-_\.:\u003a]+", "", name).lower()


def _ai_app_sec_006_check_model(model: str) -> str:
    """Raise ValueError if model is on the organisation's disapproved list."""
    normalized = _ai_app_sec_006_normalize(model)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED:
        if normalized == disapproved:
            raise ValueError(
                f"Model '{model}' is on the organisation's disapproved list and cannot be used."
            )
    return model
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
    # Social Security Number (SSN)
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (TIN) - EIN format
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'), '[REDACTED_CC]'),
    # Financial Account Number (8-17 digit standalone numbers)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Passport Number (letter(s) followed by digits)
    (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's License Number (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # Vehicle Identification Number (VIN)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Email Address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number (US and international formats)
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # Year of Birth (standalone 4-digit year 1900-2099 near birth-related keywords)
    (re.compile(r'(?i)(?:born|birth(?:day|date|place)?|dob|date of birth)[^\n]{0,30}((?:19|20)\d{2})'), '[REDACTED_YOB]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+(?:[A-Za-z]+\s){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Employee ID / School ID (common patterns like EMP-12345, ID: 12345)
    (re.compile(r'\b(?:EMP|SCH|EMPID|SCHID)[\s\-#:]?\d{4,10}\b', re.IGNORECASE), '[REDACTED_ID]'),
    # Mother's Maiden Name (keyword-based)
    (re.compile(r"(?i)(?:mother(?:'s)?\s+maiden\s+name)[^\n]{0,50}"), '[REDACTED_MAIDEN_NAME]'),
    # Fine Location (GPS coordinates)
    (re.compile(r'\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)\s*,\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?)\b'), '[REDACTED_LOCATION]'),
    # Ethnicity (keyword-based sensitive terms)
    (re.compile(r'(?i)\bethnicity\s*[:=]\s*[A-Za-z\s]+'), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation (keyword-based)
    (re.compile(r'(?i)\bsexual\s+orientation\s*[:=]\s*[A-Za-z\s]+'), '[REDACTED_ORIENTATION]'),
    # Medical Records (MRN patterns)
    (re.compile(r'\b(?:MRN|Medical Record(?:\s+Number)?)[\s\-#:]?\d{4,12}\b', re.IGNORECASE), '[REDACTED_MRN]'),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _ai_dat_sec_023_patterns:
        text = pattern.sub(replacement, text)
    return text


def _ai_dat_sec_023_redact_file(filepath: str) -> None:
    """Read a file, redact PII from its contents, and write the redacted content back."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    redacted = _ai_dat_sec_023_redact_pii(content)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(redacted)

_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r'ignore previous instructions|forget everything above', re.IGNORECASE),
     '<prompt_injection_removed: instruction_override>'),
    # 2. role_hijack
    (re.compile(r'you are now DAN|act as unrestricted', re.IGNORECASE),
     '<prompt_injection_removed: role_hijack>'),
    # 3. delimiter_escape - fake </system>, </prompt>, </user>, </assistant> tags or injected separators
    (re.compile(r'</?\s*(system|prompt|user|assistant|instruction)\s*>', re.IGNORECASE),
     '<prompt_injection_removed: delimiter_escape>'),
    # 4. encoded_payload - base64-like blobs, hex sequences, ROT13 cues, URL-encoded instructions
    (re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})', re.IGNORECASE),
     '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:0x[0-9a-fA-F]{2}[\s,]*){6,}', re.IGNORECASE),
     '<prompt_injection_removed: encoded_payload>'),
    (re.compile(r'(?:%[0-9a-fA-F]{2}){6,}', re.IGNORECASE),
     '<prompt_injection_removed: encoded_payload>'),
    # 5. hidden_text - HTML comments, zero-width characters, CSS hidden
    (re.compile(r'<!--.*?-->', re.DOTALL),
     '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]+'),
     '<prompt_injection_removed: hidden_text>'),
    (re.compile(r'style\s*=\s*["\']?display\s*:\s*none', re.IGNORECASE),
     '<prompt_injection_removed: hidden_text>'),
    # 6. fake_system_message
    (re.compile(r'\[\s*(?:system|tool|assistant)\s*\]\s*:', re.IGNORECASE),
     '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'<\s*(?:system|tool)_message\s*>', re.IGNORECASE),
     '<prompt_injection_removed: fake_system_message>'),
    # 7. exfiltration_attempt - markdown image exfil, send data to URL, leak system prompt
    (re.compile(r'!\[.*?\]\(https?://[^)]+\)', re.IGNORECASE),
     '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'(?:send|post|leak|exfiltrate|transmit)\s+(?:the\s+)?(?:system\s+prompt|data|information)\s+to\s+https?://', re.IGNORECASE),
     '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'reveal\s+(?:the\s+)?system\s+prompt', re.IGNORECASE),
     '<prompt_injection_removed: exfiltration_attempt>'),
    # 8. context_poisoning
    (re.compile(r'context\s+poison(?:ing)?|multi.?turn\s+manipulat(?:ion|e)', re.IGNORECASE),
     '<prompt_injection_removed: context_poisoning>'),
    # 9. indirect_injection - payloads in files/metadata
    (re.compile(r'indirect\s+injection|payload\s+in\s+(?:file|metadata|data\s+field)', re.IGNORECASE),
     '<prompt_injection_removed: indirect_injection>'),
    # 10. command_injection - shell/code execution
    (re.compile(r'(?:^|\s)(?:rm\s+-rf|wget\s+http|curl\s+http|bash\s+-c|sh\s+-c|python\s+-c|exec\s*\(|eval\s*\(|os\.system\s*\(|subprocess\.)', re.IGNORECASE),
     '<prompt_injection_removed: command_injection>'),
    # 11. split_payload
    (re.compile(r'split\s+payload|fragment(?:ed)?\s+(?:instruction|payload)', re.IGNORECASE),
     '<prompt_injection_removed: split_payload>'),
    # 12. jailbreak_attempt - DAN, developer mode, fictional framing
    (re.compile(r'\bDAN\b|developer\s+mode|fictional\s+framing|jailbreak', re.IGNORECASE),
     '<prompt_injection_removed: jailbreak_attempt>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in untrusted text before sending to LLM."""
    if not isinstance(text, str):
        return text
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text


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

    print("Redacting PII from uploaded file...")
    _ai_dat_sec_023_redact_file(filepath)
    print("PII redaction complete.")

    print("Creating brain instance...")

    # Sanitize file contents for prompt injection before loading into Brain
    with open(filepath, 'r', errors='replace') as _f:
        _raw_content = _f.read()
    _clean_content = _ai_app_sec_070_sanitize(_raw_content)
    if _clean_content != _raw_content:
        with open(filepath, 'w') as _f:
            _f.write(_clean_content)
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
    transcript = _ai_app_sec_070_sanitize(transcript)
    print("Transcript result: ", transcript)
    try:
        transcript = _ai_app_sec_059_check_prompt(transcript)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    print("Getting response...")
    _ai_app_sec_006_check_model(getattr(brain, 'llm_name', 'quivr-brain'))
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
            _ai_app_sec_006_check_model("whisper-1")
            transcript_response = openai.audio.transcriptions.create(
                model="whisper-1", file=f
            )
        transcript = transcript_response.text
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
