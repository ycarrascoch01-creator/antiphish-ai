"""
Motor de análisis AntiPhish AI.
Evalúa correos/mensajes de texto y URLs para detectar intentos de phishing
utilizando expresiones regulares, heurísticas de ciberseguridad y scoring.
"""

import re
from typing import Any


# ---------------------------------------------------------------------------
# Constantes compartidas
# ---------------------------------------------------------------------------

URGENCY_KEYWORDS = [
    r"urgente", r"inmediato", r"ahora mismo", r"24 horas", r"plazo l",
    r"expira", r"vence", r"sin demora", r"rápido", r"alertas",
    r"cuenta bloqueada", r"cuenta suspendida", r"acceso restringido",
    r"verificación urgente", r"actualización urgente",
]

BANK_SPOOFING_KEYWORDS = [
    r"banco", r"bbva", r"santander", r"caixa", r"bankia", r"ing",
    r"sabadell", r"openbank", r"unicaja", r"iberextra", r"bankinter",
    r"transferencia", r"nominan", r"nóminas", r"tarjeta de crédito",
    r"tarjeta de débito", r"cajero automático", r"home banking",
    r"banca online", r"banca por internet",
]

SUSPICIOUS_CTA_KEYWORDS = [
    r"haga clic aquí", r"clic aquí", r"clic en", r"pincha aquí",
    r"verifica tu cuenta", r"verificar cuenta", r"confirma tu identidad",
    r"iniciar sesión", r"inicia sesión", r"acceder ahora",
    r"descargar adjunto", r"abrir documento", r"revisar factura",
]

DECEPTIVE_LINK_PATTERNS = [
    r"bit\.ly", r"tinyurl", r"t\.co", r"goo\.gl", r"ow\.ly",
    r"shorturl", r"cutt\.ly", r"rebrand\.ly",
]

KNOWN_BRANDS = [
    "paypal", "amazon", "facebook", "instagram", "linkedin",
    "microsoft", "apple", "google", "netflix", "dhl",
    "correos", "seur", "mrw", "nacex",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".download", ".loan", ".win",
    ".review", ".country", ".stream", ".gq", ".cf", ".ml",
    ".tk", ".men", ".work", ".party",
]


def _score_level(score: int) -> str:
    """Convierte un puntaje numérico en un nivel textual."""
    if score <= 30:
        return "SEGURO"
    if score <= 69:
        return "SOSPECHOSO"
    return "ALTO RIESGO / PHISHING"


def _recommendation_for_level(level: str, is_url: bool = False) -> str:
    """Devuelve una recomendación de acción según el nivel de riesgo."""
    if level == "SEGURO":
        if is_url:
            return "El enlace parece seguro. No obstante, siempre verifica que el dominio sea el correcto antes de ingresar datos personales."
        return "El mensaje no muestra indicios evidentes de phishing. Mantén las precauciones habituales."

    if level == "SOSPECHOSO":
        if is_url:
            return ("Este enlace presenta señales de alerta. No ingreses credenciales ni datos sensibles. "
                    "Verifica la dirección del remitente y accede al sitio oficial escribiendo la URL manualmente en el navegador.")
        return ("Este mensaje presenta señales de alerta. No hagas clic en enlaces ni descargues adjuntos. "
                "Si dice ser de tu banco o servicio conocido, contacta con ellos por canales oficiales.")

    if is_url:
        return ("ENLACE PELIGROSO. No abras este enlace bajo ninguna circunstancia. "
                "Es muy probablemente un sitio de phishing diseñado para robar tus credenciales o datos bancarios.")
    return ("MENSAJE DE PHISHING. No respondas, no hagas clic en ningún enlace y no descargues adjuntos. "
            "Elimina el mensaje y, si es de una entidad bancaria, repórtalo a través de sus canales oficiales.")


# ---------------------------------------------------------------------------
# Análisis de correo / mensaje de texto
# ---------------------------------------------------------------------------

def analyze_email(text: str) -> dict[str, Any]:
    """
    Analiza un correo o mensaje de texto y devuelve un diccionario con:
        risk_score (int), level (str), flags (list[str]),
        recommendation (str), details (dict)
    """
    flags: list[str] = []
    details: dict[str, Any] = {
        "urgency_hits": [],
        "bank_spoofing_hits": [],
        "cta_hits": [],
        "deceptive_links": [],
        "suspicious_urls": [],
    }

    text_lower = text.lower()

    # 1. Lenguaje de urgencia / presión
    for pattern in URGENCY_KEYWORDS:
        matches = re.findall(pattern, text_lower, flags=re.IGNORECASE)
        if matches:
            details["urgency_hits"].extend(matches)
            flags.append(f"Lenguaje de urgencia detectado: '{pattern}'")

    # 2. Keywords de suplantación bancaria
    for pattern in BANK_SPOOFING_KEYWORDS:
        matches = re.findall(pattern, text_lower, flags=re.IGNORECASE)
        if matches:
            details["bank_spoofing_hits"].extend(matches)
            flags.append(f"Posible suplantación bancaria: '{pattern}'")

    # 3. Llamadas a la acción sospechosas
    for pattern in SUSPICIOUS_CTA_KEYWORDS:
        matches = re.findall(pattern, text_lower, flags=re.IGNORECASE)
        if matches:
            details["cta_hits"].extend(matches)
            flags.append(f"Llamada a la acción sospechosa: '{pattern}'")

    # 4. Enlaces acortados / engañosos
    for pattern in DECEPTIVE_LINK_PATTERNS:
        matches = re.findall(pattern, text_lower, flags=re.IGNORECASE)
        if matches:
            details["deceptive_links"].extend(matches)
            flags.append(f"Enlazador de URL acortado detectado: '{pattern}'")

    # 5. URLs dentro del texto
    url_pattern = re.compile(r"https?://[^\s]+", flags=re.IGNORECASE)
    found_urls = url_pattern.findall(text)
    details["suspicious_urls"] = found_urls
    for url in found_urls:
        url_lower = url.lower()
        # Verificar si la URL usa un acortador
        if any(s in url_lower for s in ["bit.ly", "tinyurl", "t.co", "goo.gl"]):
            flags.append(f"URL acortada sospechosa: {url}")
        # Verificar TLD sospechosos
        if any(tld in url_lower for tld in SUSPICIOUS_TLDS):
            flags.append(f"Dominio con TLD sospechoso: {url}")

    # --- Cálculo del puntaje ---
    score = 0
    score += min(len(details["urgency_hits"]) * 10, 30)
    score += min(len(details["bank_spoofing_hits"]) * 10, 25)
    score += min(len(details["cta_hits"]) * 8, 25)
    score += min(len(details["deceptive_links"]) * 10, 20)
    score = min(score, 100)

    level = _score_level(score)
    recommendation = _recommendation_for_level(level, is_url=False)

    return {
        "risk_score": score,
        "level": level,
        "flags": flags,
        "recommendation": recommendation,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Análisis de URL
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> dict[str, Any]:
    """
    Analiza una URL y devuelve un diccionario con:
        risk_score (int), level (str), flags (list[str]),
        recommendation (str), details (dict)
    """
    flags: list[str] = []
    details: dict[str, Any] = {
        "uses_https": False,
        "subdomain_count": 0,
        "suspicious_tld": False,
        "homograph_risk": False,
        "brand_in_domain": False,
        "special_chars": False,
        "domain": "",
        "tld": "",
    }

    url = url.strip()

    # Normalizar esquema
    if not url.startswith(("http://", "https://")):
        url_to_parse = "http://" + url
        flags.append("La URL no especifica esquema (http/https).")
    else:
        url_to_parse = url

    # Extraer host básico (sin depender de urllib para mantener KISS)
    host_part = re.sub(r"^https?://", "", url_to_parse, flags=re.IGNORECASE)
    host_part = re.sub(r"[:/].*$", "", host_part)

    details["domain"] = host_part

    # HTTPS
    if url.lower().startswith("https://"):
        details["uses_https"] = True
    else:
        flags.append("La URL no usa HTTPS (falta cifrado TLS).")

    # Subdominios: contar puntos en el host
    subdomain_count = host_part.count(".")
    details["subdomain_count"] = subdomain_count
    if subdomain_count >= 4:
        flags.append(f"Exceso de subdominios ({subdomain_count} puntos en el dominio).")
    elif subdomain_count == 3:
        flags.append("Múltiples subdominios detectados (posible ofuscación).")

    # TLD sospechoso
    for tld in SUSPICIOUS_TLDS:
        if host_part.lower().endswith(tld):
            details["suspicious_tld"] = True
            flags.append(f"TLD de alto riesgo detectado: {tld}")
            break

    # Caracteres extraños en el dominio
    if re.search(r"[^\w.\-]", host_part):
        details["special_chars"] = True
        flags.append("El dominio contiene caracteres especiales inusuales.")

    # Homóglifos simples: caracteres cirílicos que se parecen al latino
    homograph_chars = set("аеиорсухАЕИОРСУХ")
    if any(ch in homograph_chars for ch in host_part):
        details["homograph_risk"] = True
        flags.append("Posible ataque de homóglifos (caracteres cirílicos en el dominio).")

    # Marca conocida en el dominio (phishing de marca)
    host_lower = host_part.lower()
    for brand in KNOWN_BRANDS:
        if brand in host_lower:
            details["brand_in_domain"] = True
            main_domain = host_part.split(".")[-2] if subdomain_count >= 1 else host_part.split(".")[0]
            if brand != main_domain.lower():
                flags.append(f"La marca '{brand}' aparece en el dominio pero no como titular principal (posible suplantación).")
            break

    # --- Cálculo del puntaje ---
    score = 0
    if not details["uses_https"]:
        score += 15
    if details["subdomain_count"] >= 4:
        score += 20
    elif details["subdomain_count"] == 3:
        score += 10
    if details["suspicious_tld"]:
        score += 20
    if details["homograph_risk"]:
        score += 25
    if details["special_chars"]:
        score += 10
    if details["brand_in_domain"]:
        score += 15

    score = min(score, 100)
    level = _score_level(score)
    recommendation = _recommendation_for_level(level, is_url=True)

    return {
        "risk_score": score,
        "level": level,
        "flags": flags,
        "recommendation": recommendation,
        "details": details,
    }