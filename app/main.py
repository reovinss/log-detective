from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.analyzer import analyze_logs


BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_LOG = BASE_DIR / "samples" / "nginx_access.log"

app = FastAPI(title="Log Detective")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    sample = SAMPLE_LOG.read_text(encoding="utf-8") if SAMPLE_LOG.exists() else ""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "sample": sample,
            "log_text": "",
            "result": None,
        },
    )


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    log_text: str = Form(""),
    log_file: UploadFile | None = File(None),
) -> HTMLResponse:
    uploaded_text = ""
    if log_file and log_file.filename:
        uploaded_text = (await log_file.read()).decode("utf-8", errors="replace")

    text = uploaded_text or log_text
    sample = SAMPLE_LOG.read_text(encoding="utf-8") if SAMPLE_LOG.exists() else ""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "sample": sample,
            "log_text": text,
            "result": analyze_logs(text) if text.strip() else None,
        },
    )
