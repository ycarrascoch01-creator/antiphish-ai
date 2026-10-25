"""
Servidor FastAPI para AntiPhish AI.
Expone endpoints para analizar correos/mensajes y URLs mediante el motor
de detector.py, y sirve el frontend estático.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from detector import analyze_email, analyze_url

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="AntiPhish AI", version="1.0.0")

# Montar archivos estáticos
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ---------------------------------------------------------------------------
# Modelos de petición
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    content: str


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Sirve el dashboard principal."""
    html_path = BASE_DIR / "templates" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"), status_code=200)


@app.post("/analyze/email")
async def analyze_email_endpoint(payload: AnalyzeRequest):
    """Analiza un correo o mensaje de texto."""
    result = analyze_email(payload.content)
    return JSONResponse(content=result)


@app.post("/analyze/url")
async def analyze_url_endpoint(payload: AnalyzeRequest):
    """Analiza una URL / enlace web."""
    result = analyze_url(payload.content)
    return JSONResponse(content=result)