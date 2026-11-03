import re
import sqlite3
import unicodedata
from typing import Any


KNOWLEDGE_ITEMS = (
    (
        "deteccion",
        "La urgencia no demuestra legitimidad",
        "urgente urgencia plazo inmediato bloqueo suspendida cuenta pago premio",
        "Los mensajes que presionan para actuar rápido, amenazan con cerrar una cuenta o prometen premios inesperados son señales de alerta. Verifica la solicitud por un canal que ya conozcas.",
        "Federal Trade Commission",
        "https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams",
    ),
    (
        "deteccion",
        "Comprueba el destino de cada enlace",
        "enlace url dominio sitio web login iniciar sesion credenciales acortador",
        "No confíes solo en el nombre visible de un enlace. Revisa el dominio completo y, si tienes dudas, abre el sitio oficial escribiendo su dirección conocida en el navegador.",
        "Google Gmail Help",
        "https://support.google.com/mail/answer/8253?hl=es",
    ),
    (
        "deteccion",
        "Desconfia de solicitudes inesperadas de datos",
        "contrasena password codigo verificacion tarjeta banco pago informacion personal financiera",
        "No entregues contraseñas, códigos de un solo uso ni datos financieros desde un enlace recibido por mensaje. Contacta a la organización usando un teléfono o sitio que ya sepas que es auténtico.",
        "Federal Trade Commission",
        "https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams",
    ),
    (
        "deteccion",
        "Adjuntos inesperados pueden ser peligrosos",
        "adjunto archivo factura documento descargar abrir malware",
        "Un archivo o una factura inesperada puede instalar software malicioso. Confirma con el remitente por otro canal antes de abrir adjuntos o habilitar contenido activo.",
        "Federal Trade Commission",
        "https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams",
    ),
    (
        "prevencion",
        "Activa la autenticación multifactor",
        "mfa multifactor autenticacion dos factores codigo cuenta contrasena",
        "Activa autenticación multifactor en correo, banca y cuentas importantes. Si una contraseña queda expuesta, el segundo factor puede impedir el acceso no autorizado.",
        "Federal Trade Commission",
        "https://consumer.ftc.gov/articles/use-two-factor-authentication-protect-your-accounts",
    ),
    (
        "respuesta",
        "Si ingresaste tus credenciales, cambia la contraseña",
        "respondi credenciales contrasena password cuenta robada comprometida acceso",
        "Cambia de inmediato la contraseña desde el sitio o la aplicación oficial, cierra sesiones desconocidas y activa MFA. Si reutilizaste esa contraseña, cámbiala también en los otros servicios.",
        "Federal Trade Commission",
        "https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams",
    ),
    (
        "respuesta",
        "Reporta el mensaje sospechoso",
        "reportar denunciar correo email sms mensaje phishing estafa",
        "Reporta el mensaje desde las herramientas de tu proveedor de correo o teléfono y ante el organismo de protección al consumidor o equipo nacional de respuesta a incidentes de tu país. No reenvíes el enlace a otras personas.",
        "NCSC UK",
        "https://www.ncsc.gov.uk/collection/phishing-scams",
    ),
    (
        "respuesta",
        "Si abriste un archivo, revisa el dispositivo",
        "abri archivo adjunto descargue malware virus dispositivo computadora movil",
        "Actualiza el software de seguridad y ejecuta un análisis del dispositivo. Si detectas actividad sospechosa, desconéctalo de la red y solicita ayuda al equipo de soporte correspondiente.",
        "Federal Trade Commission",
        "https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams",
    ),
    (
        "deteccion",
        "La suplantación puede imitar a una persona conocida",
        "suplantacion marca banco empresa remitente identidad familiar colega compania",
        "Un logotipo, nombre de empresa o nombre de una persona conocida no autentica el mensaje. Comprueba cuidadosamente la dirección del remitente y confirma solicitudes inusuales por otro canal.",
        "Google Gmail Help",
        "https://support.google.com/mail/answer/8253?hl=es",
    ),
    (
        "prevencion",
        "Usa las herramientas para reportar phishing",
        "gmail proveedor correo spam phishing reportar marcar sospechoso",
        "Marca el mensaje como phishing en tu proveedor de correo. El reporte ayuda a mejorar los filtros y evita que otros usuarios reciban mensajes similares.",
        "Google Gmail Help",
        "https://support.google.com/mail/answer/8253?hl=es",
    ),
    (
        "deteccion",
        "El phishing tambien llega por SMS y llamadas",
        "sms smishing mensaje texto llamada telefono enlace premio codigo",
        "Los intentos de fraude pueden llegar por correo, SMS, sitios web, anuncios o llamadas. No uses números ni enlaces incluidos en el mensaje para verificar una solicitud.",
        "NCSC UK",
        "https://www.ncsc.gov.uk/collection/phishing-scams",
    ),
)


def _create_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE knowledge (
            id INTEGER PRIMARY KEY,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            keywords TEXT NOT NULL,
            guidance TEXT NOT NULL,
            source_name TEXT NOT NULL,
            source_url TEXT NOT NULL
        )"""
    )
    connection.executemany(
        """INSERT INTO knowledge
            (category, title, keywords, guidance, source_name, source_url)
            VALUES (?, ?, ?, ?, ?, ?)""",
        KNOWLEDGE_ITEMS,
    )
    connection.commit()
    return connection


_DATABASE = _create_database()


def search_knowledge(query: str = "", limit: int = 5) -> list[dict[str, Any]]:
    normalized_query = unicodedata.normalize("NFKD", query).encode("ascii", "ignore").decode("ascii")
    tokens = {
        token
        for token in re.findall(r"[a-z0-9]+", normalized_query.lower())
        if len(token) > 2
    }
    rows = _DATABASE.execute("SELECT * FROM knowledge").fetchall()
    ranked: list[tuple[int, sqlite3.Row]] = []

    for row in rows:
        searchable = unicodedata.normalize("NFKD", " ".join(
            str(row[column])
            for column in ("category", "title", "keywords", "guidance")
        )).encode("ascii", "ignore").decode("ascii").lower()
        relevance = sum(token in searchable for token in tokens)
        if not tokens or relevance:
            ranked.append((relevance, row))

    ranked.sort(key=lambda result: (-result[0], result[1]["title"]))
    return [
        {
            "category": row["category"],
            "title": row["title"],
            "guidance": row["guidance"],
            "source_name": row["source_name"],
            "source_url": row["source_url"],
        }
        for _, row in ranked[: max(1, min(limit, 50))]
    ]
