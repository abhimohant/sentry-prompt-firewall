from typing import Any, Literal

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.app.firewall import analyze_segments, extract_file_segments, extract_segments, guard_tool_call


app = FastAPI(title="Prompt Firewall", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, max_length=1_000_000)
    input_format: Literal["text", "html", "email"] = "text"


class ToolGuardRequest(BaseModel):
    user_request: str = Field(min_length=1, max_length=10_000)
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    segments = extract_segments(request.content, request.input_format)
    result = analyze_segments(segments)
    result["sources"] = sorted({segment["source"] for segment in segments})
    result["extracted_text"] = "\n".join(segment["text"] for segment in segments)[:20_000]
    return result


@app.post("/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
) -> dict[str, Any]:
    content = await file.read(10_000_001)
    if len(content) > 10_000_000:
        raise HTTPException(status_code=413, detail="Files must be 10 MB or smaller.")
    try:
        segments = extract_file_segments(file.filename or "upload.txt", content)
    except (ValueError, UnicodeDecodeError) as error:
        raise HTTPException(status_code=415, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=422, detail=f"Could not extract this file: {error}") from error

    result = analyze_segments(segments)
    result["sources"] = sorted({segment["source"] for segment in segments})
    result["extracted_text"] = "\n".join(segment["text"] for segment in segments)[:20_000]
    result["filename"] = file.filename
    return result


@app.post("/tool-guard")
def check_tool_call(request: ToolGuardRequest) -> dict[str, Any]:
    return guard_tool_call(request.user_request, request.tool_name, request.arguments)
