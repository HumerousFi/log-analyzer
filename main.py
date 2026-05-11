from fastapi import FastAPI, File, HTTPException, UploadFile

from models import LogAnalysisResponse
from parser import analyze_log_content

app = FastAPI(title="Log Analyzer API")


@app.get("/")
async def root():
    return {"status": "running"}


@app.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_log(
    file: UploadFile = File(...)
):
    if not file.filename.endswith(".log"):
        raise HTTPException(
            status_code=400,
            detail="Only .log files supported"
        )

    content = await file.read()

    text = content.decode(
        "utf-8",
        errors="ignore"
    )

    return analyze_log_content(text)