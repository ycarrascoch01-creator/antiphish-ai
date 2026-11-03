"""
Servidor FastAPI para AntiPhish AI.
Expone endpoints para analizar correos/mensajes y URLs mediante el motor
de detector.py, y sirve el frontend est├ítico.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from detector import analyze_email, analyze_url
from knowledge_base import search_knowledge

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="AntiPhish AI", version="1.0.0")

# Montar archivos est├íticos
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ---------------------------------------------------------------------------
# Modelos de petici├│n
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
    return HTMLResponse(content=html_path.read_text(encoding="utf-16"), status_code=200)


@app.get("/knowledge")
async def knowledge(q: str = "", limit: int = 20):
    return {"items": search_knowledge(q, limit)}


@app.post("/analyze/email")
async def analyze_email_endpoint(payload: AnalyzeRequest):
    """Analiza un correo o mensaje de texto."""
    result = analyze_email(payload.content)
    result["knowledge"] = search_knowledge(
        " ".join(result["flags"]) or payload.content, limit=3
    )
    if not result["knowledge"] and result["flags"]:
        result["knowledge"] = search_knowledge(payload.content, limit=3)
    return JSONResponse(content=result)


@app.post("/analyze/url")
async def analyze_url_endpoint(payload: AnalyzeRequest):
    """Analiza una URL / enlace web."""
    result = analyze_url(payload.content)
    result["knowledge"] = search_knowledge(
        " ".join(result["flags"]) or payload.content, limit=3
    )
    if not result["knowledge"] and result["flags"]:
        result["knowledge"] = search_knowledge(payload.content, limit=3)
    return JSONResponse(content=result)

