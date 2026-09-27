from flask import Flask, render_template, request, jsonify, session
import openai
import base64
import hashlib
import hmac
import json
from datetime import datetime
import os
import requests
from dotenv import load_dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from tempfile import NamedTemporaryFile
from werkzeug.utils import secure_filename
from asyncio import to_thread
import asyncio


UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or (_ for _ in ()).throw(RuntimeError("FLASK_SECRET_KEY environment variable is not set"))
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["CACHE_TYPE"] = "SimpleCache"  # In-memory cache for development
app.config["CACHE_DEFAULT_TIMEOUT"] = 60 * 60  # 1 hour cache timeout
load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")

brains = {}


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


import logging

llm_logger = logging.getLogger("llm_interactions")
if not llm_logger.handlers:
    _llm_handler = logging.StreamHandler()
    _llm_handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s %(llm_interaction)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    llm_logger.addHandler(_llm_handler)
    llm_logger.setLevel(logging.INFO)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ⚠️  POLICY VIOLATION — LLM ENDPOINT WITHOUT AUTHENTICATION
# This endpoint invokes LLM inference (Brain.from_files) and is reachable by
# ANY unauthenticated caller. Per policy, all LLM endpoints MUST require
# authentication before processing requests. Authentication (e.g. session
# validation, API key check, or OAuth token verification) must be implemented
# before this endpoint is used in any non-local environment.
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


# ⚠️  POLICY VIOLATION — LLM ENDPOINT WITHOUT AUTHENTICATION
# This endpoint invokes LLM inference (brain.ask, Whisper transcription, TTS)
# and is reachable by ANY unauthenticated caller. Per policy, all LLM endpoints
# MUST require authentication before processing requests. Authentication (e.g.
# session validation, API key check, or OAuth token verification) must be
# implemented before this endpoint is used in any non-local environment.
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

    print("Getting response...")
    llm_logger.info(
        "LLM interaction - RAG query request",
        extra={
            "llm_interaction": {
                "type": "rag_query",
                "model": "brain.ask",
                "input": {"transcript": transcript},
            }
        },
    )
    quivr_response = await to_thread(run_in_event_loop, brain.ask, transcript)
    llm_logger.info(
        "LLM interaction - RAG query response",
        extra={
            "llm_interaction": {
                "type": "rag_query",
                "model": "brain.ask",
                "output": {"answer": quivr_response.answer},
            }
        },
    )
    safe_answer = sanitize_llm_output(quivr_response.answer)

        print("Text to speech...")
    audio_base64 = synthesize_speech(quivr_response.answer)

    print("Building provenance envelope...")
    try:
        envelope = _build_provenance_envelope(
            audio_b64=audio_base64,
            answer_text=quivr_response.answer,
            prompt_text=transcript,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return jsonify({"error": "Content generation failed provenance checks."}), 500

    print("Done")
    return jsonify(envelope)


# Patterns that indicate dynamic code execution primitives
_DANGEROUS_PATTERNS = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bsubprocess\s*\.\s*\w*\s*\([^)]*shell\s*=\s*True",
    r"\b__import__\s*\(",
    r"\bcompile\s*\(",
    r"\bexecfile\s*\(",
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bcommands\.getoutput\s*\(",
    r"\bgetattr\s*\(",
    r"\bsetattr\s*\(",
    r"\bdelattr\s*\(",
    r"<script[^>]*>",
    r"javascript\s*:",
    r"\$\(\s*['\"].*eval",
    r"Function\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"bash\s+-c",
    r"sh\s+-c",
    r"\bpickle\.loads\s*\(",
    r"\byaml\.load\s*\(",
]


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    import re
    if not isinstance(text, str):
        return ""
    lines = text.splitlines()
    safe_lines = []
    for line in lines:
        is_dangerous = False
        for pattern in _DANGEROUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                print(f"[SECURITY] Removed dangerous line from LLM output: {line!r}")
                is_dangerous = True
                break
        if not is_dangerous:
            safe_lines.append(line)
    return "\n".join(safe_lines)


def transcribe_audio_file(audio_file):
    with NamedTemporaryFile(suffix=".webm", delete=False) as temp_audio_file:
        audio_file.save(temp_audio_file)
        temp_audio_file_path = temp_audio_file.name

    try:
        with open(temp_audio_file_path, "rb") as f:
            llm_logger.info(
                "LLM interaction - Whisper transcription request",
                extra={
                    "llm_interaction": {
                        "type": "transcription",
                        "model": "whisper-1",
                        "input": {"file": temp_audio_file_path},
                    }
                },
            )
            transcript_response = openai.audio.transcriptions.create(
                model="whisper-1", file=f
            )
        transcript = transcript_response.text
        llm_logger.info(
            "LLM interaction - Whisper transcription response",
            extra={
                "llm_interaction": {
                    "type": "transcription",
                    "model": "whisper-1",
                    "output": {"transcript": transcript},
                }
            },
        )
    finally:
        os.unlink(temp_audio_file_path)

    return transcript


def synthesize_speech(text):
    llm_logger.info(
        "LLM interaction - TTS synthesis request",
        extra={
            "llm_interaction": {
                "type": "tts",
                "model": "tts-1",
                "input": {"voice": "nova", "text": text},
            }
        },
    )
    speech_response = openai.audio.speech.create(
        model="tts-1", voice="nova", input=text
    )
    audio_content = speech_response.content
    llm_logger.info(
        "LLM interaction - TTS synthesis response",
        extra={
            "llm_interaction": {
                "type": "tts",
                "model": "tts-1",
                "output": {"audio_content_bytes": len(audio_content)},
            }
        },
    )
    audio_base64 = base64.b64encode(audio_content).decode("utf-8")
    return audio_base64


if __name__ == "__main__":
    app.run(debug=True)
