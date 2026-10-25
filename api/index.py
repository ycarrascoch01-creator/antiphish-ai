import sys
import os

# Agregar el directorio raíz al path para importar main
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app

# Handler para Vercel serverless (Python runtime)
# Vercel pasa el request y contexto como argumentos
def handler(request, context):
    try:
        from mangum import Mangum
        asgi_handler = Mangum(app)
        return asgi_handler(request, context)
    except ImportError:
        # Fallback: retornar info basica si mangum no esta disponible
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"message":"AntiPhish AI API - desplegado en Vercel","endpoints":{"GET /":"dashboard","POST /analyze/email":"analizar correo","POST /analyze/url":"analizar URL"}}'
        }
