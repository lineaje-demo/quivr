import tempfile
import os
import chainlit as cl
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from openai import AsyncOpenAI
from chainlit.element import Element

from io import BytesIO


import re

# Patterns for dynamic code execution primitives that must be removed
_DANGEROUS_PATTERNS = re.compile(
    r"(?m)^.*"
    r"(?:"
    r"\beval\s*\("
    r"|\bexec\s*\("
    r"|\bsubprocess\s*\.\s*(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True"
    r"|\bos\.system\s*\("
    r"|\bos\.popen\s*\("
    r"|\b__import__\s*\("
    r"|\bcompile\s*\("
    r"|\bexecfile\s*\("
    r"|\binput\s*\(.*\beval"
    r"|<script[^>]*>[\s\S]*?</script>"
    r"|javascript\s*:"
    r"|bash\s+-c"
    r"|\$\(.*\)"
    r"|`[^`]*`"
    r").*$",
    re.IGNORECASE,
)


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    if not text:
        return text
    sanitized = _DANGEROUS_PATTERNS.sub("", text)
    # Collapse multiple consecutive blank lines left by removed lines
    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)
    return sanitized.strip()


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


import re

def mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories before displaying on UI."""
    if not isinstance(text, str):
        return text
    # Social Security Number (SSN): 123-45-6789 or 123456789
    text = re.sub(r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b', '[SSN REDACTED]', text)
    # Taxpayer Identification Number (TIN): same pattern as SSN / EIN 12-3456789
    text = re.sub(r'\b\d{2}-\d{7}\b', '[TIN REDACTED]', text)
    # Credit Card Number: 13-19 digit sequences (with or without spaces/dashes)
    text = re.sub(r'\b(?:\d[ -]?){13,19}\b', '[CC REDACTED]', text)
    # Passport Number: letter(s) followed by 6-9 digits
    text = re.sub(r'\b[A-Z]{1,2}\d{6,9}\b', '[PASSPORT REDACTED]', text)
    # Driver's License: common formats (letter + digits or all digits 8-12)
    text = re.sub(r'\b[A-Z]{1,2}\d{6,8}\b', '[DL REDACTED]', text)
    # Financial Account Number: 8-17 digit sequences not already caught
    text = re.sub(r'\b\d{8,17}\b', '[ACCOUNT REDACTED]', text)
    # Email address
    text = re.sub(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[EMAIL REDACTED]', text)
    # Personal Phone Number: various formats
    text = re.sub(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b', '[PHONE REDACTED]', text)
    # IP Address (IPv4)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP REDACTED]', text)
    # MAC Address
    text = re.sub(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', '[MAC REDACTED]', text)
    # Vehicle Identification Number (VIN): 17 alphanumeric chars
    text = re.sub(r'\b[A-HJ-NPR-Z0-9]{17}\b', '[VIN REDACTED]', text)
    # Year of Birth patterns (e.g. DOB: 1985, Born: 1972)
    text = re.sub(r'(?i)\b(?:dob|date of birth|born|birth year)[:\s]+\d{4}\b', '[DOB REDACTED]', text)
    return text


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
    logger.info("LLM interaction start: brain.ask_streaming | input: %s | retrieval_config: %s", message.content, retrieval_config)
    full_response_chunks = []
    async for chunk in brain.ask_streaming(message.content, retrieval_config=retrieval_config):
        safe_answer = sanitize_llm_output(chunk.answer)
        await msg.stream_token(safe_answer)
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)
                print(source)
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=mask_pii(source.page_content), display="side"))
    
    think.status = cl.TaskStatus.DONE
    tts.status = cl.TaskStatus.RUNNING
    await task_list.update()
    
    safe_tts_input = sanitize_llm_output(msg.content)
    audio_file = await text_to_speech(safe_tts_input)
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
    response = await async_openai_client.audio.transcriptions.create(
        model="whisper-1", file=audio_file
    )

    return sanitize_llm_output(response.text)

@cl.step(type="tool", name="Text to speech")
async def text_to_speech(text):
    logger.info("LLM interaction start: audio.speech.create | model: tts-1 | voice: alloy | input: %s", text)
    response = await async_openai_client.audio.speech.create(
        model="tts-1", voice="alloy", input=text
    )
    logger.info("LLM interaction end: audio.speech.create | output_size_bytes: %d", len(response.content))
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

    msg = cl.Message(author="You", content=transcription, elements=elements)

    stt.status = cl.TaskStatus.DONE
    task_list.status = "Done"
    await task_list.update()
    await cl.sleep(1)
    await task_list.remove()

    await main(message=msg)