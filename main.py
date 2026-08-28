from dotenv import load_dotenv

load_dotenv()

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

import auth
import billing
from auth import get_current_user, require_active_subscription
from db import User, get_db, init_db
from models import LogAnalysisResponse
from parser import analyze_log_content

app = FastAPI(title="Security Log Analyzer")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

app.include_router(auth.router)
app.include_router(billing.router)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.exception_handler(StarletteHTTPException)
async def redirect_on_auth_errors(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 303 and "Location" in (exc.headers or {}):
        return RedirectResponse(url=exc.headers["Location"], status_code=303)
    return await http_exception_handler(request, exc)


@app.get("/")
def landing(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse(request, "landing.html", {"user": user})


@app.get("/pricing")
def pricing(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    subscribed = bool(user and user.subscription and user.subscription.is_active)
    return templates.TemplateResponse(
        request, "pricing.html", {"user": user, "subscribed": subscribed}
    )


@app.get("/dashboard")
def dashboard(request: Request, user: User = Depends(require_active_subscription)):
    return templates.TemplateResponse(request, "dashboard.html", {"user": user})


# --- Analysis API (existing tool, unchanged for now; the dashboard above will
#     be wired up to this once the analyzer itself is ready to ship) ---


@app.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_log(file: UploadFile = File(...)):
    if not file.filename.endswith(".log"):
        raise HTTPException(status_code=400, detail="Only .log files supported")

    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    return analyze_log_content(text)
