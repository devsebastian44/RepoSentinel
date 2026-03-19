"""
rules/patterns.py — Reglas de detección basadas en expresiones regulares.

Cada regla es un dict con:
  - id:          Identificador único.
  - name:        Nombre descriptivo.
  - description: Explicación de qué detecta.
  - severity:    'critical' | 'high' | 'medium' | 'low'
  - pattern:     Regex compilada.
  - category:    Categoría temática (api_keys, credentials, tokens, etc.)
"""

from __future__ import annotations

import re
from typing import TypedDict


class Rule(TypedDict):
    id:          str
    name:        str
    description: str
    severity:    str
    pattern:     re.Pattern
    category:    str


def _r(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    """Helper para compilar regex con manejo de errores."""
    return re.compile(pattern, flags)


# ══════════════════════════════════════════════════════════════════════════════
# REGLAS — Secretos de proveedores cloud y servicios populares
# ══════════════════════════════════════════════════════════════════════════════

RULES: list[Rule] = [

    # ── AWS ───────────────────────────────────────────────────────────────────
    {
        "id":          "AWS_ACCESS_KEY",
        "name":        "AWS Access Key ID",
        "description": "Clave de acceso de AWS que permite autenticarse en los servicios de Amazon.",
        "severity":    "critical",
        "pattern":     _r(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        "category":    "cloud_credentials",
    },
    {
        "id":          "AWS_SECRET_KEY",
        "name":        "AWS Secret Access Key",
        "description": "Clave secreta de AWS; combinada con el Access Key da acceso completo.",
        "severity":    "critical",
        "pattern":     _r(
            r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s\"'`]*[:=][\s\"'`]*([A-Za-z0-9/+=]{40})"
        ),
        "category":    "cloud_credentials",
    },
    {
        "id":          "AWS_SESSION_TOKEN",
        "name":        "AWS Session Token",
        "description": "Token de sesión temporal de AWS STS.",
        "severity":    "high",
        "pattern":     _r(r"(?i)aws[_\-\s]?session[_\-\s]?token[\s\"'`]*[:=][\s\"'`]*([A-Za-z0-9/+=]{100,})"),
        "category":    "cloud_credentials",
    },

    # ── Google ────────────────────────────────────────────────────────────────
    {
        "id":          "GOOGLE_API_KEY",
        "name":        "Google API Key",
        "description": "Clave de API de Google Cloud / Maps / Firebase.",
        "severity":    "high",
        "pattern":     _r(r"AIza[0-9A-Za-z\-_]{35}"),
        "category":    "cloud_credentials",
    },
    {
        "id":          "GOOGLE_OAUTH_CLIENT",
        "name":        "Google OAuth Client Secret",
        "description": "Secreto de cliente OAuth de Google.",
        "severity":    "high",
        "pattern":     _r(r"GOCSPX-[0-9A-Za-z\-_]{28}"),
        "category":    "oauth",
    },
    {
        "id":          "GOOGLE_SERVICE_ACCOUNT",
        "name":        "Google Service Account Key",
        "description": "Clave de cuenta de servicio de GCP en formato JSON.",
        "severity":    "critical",
        "pattern":     _r(r'"type"\s*:\s*"service_account"'),
        "category":    "cloud_credentials",
    },
    {
        "id":          "FIREBASE_URL",
        "name":        "Firebase Database URL",
        "description": "URL de base de datos Firebase que podría estar abierta.",
        "severity":    "medium",
        "pattern":     _r(r"https://[a-z0-9\-]+\.firebaseio\.com"),
        "category":    "cloud_credentials",
    },

    # ── GitHub ────────────────────────────────────────────────────────────────
    {
        "id":          "GITHUB_PAT_CLASSIC",
        "name":        "GitHub Personal Access Token (Classic)",
        "description": "Token de acceso personal clásico de GitHub.",
        "severity":    "critical",
        "pattern":     _r(r"ghp_[0-9A-Za-z]{36}"),
        "category":    "tokens",
    },
    {
        "id":          "GITHUB_PAT_FINE",
        "name":        "GitHub Fine-Grained PAT",
        "description": "Token de acceso personal de granularidad fina de GitHub.",
        "severity":    "critical",
        "pattern":     _r(r"github_pat_[0-9A-Za-z_]{82}"),
        "category":    "tokens",
    },
    {
        "id":          "GITHUB_OAUTH_TOKEN",
        "name":        "GitHub OAuth App Token",
        "description": "Token OAuth de aplicación de GitHub.",
        "severity":    "critical",
        "pattern":     _r(r"gho_[0-9A-Za-z]{36}"),
        "category":    "tokens",
    },
    {
        "id":          "GITHUB_APP_TOKEN",
        "name":        "GitHub App Token",
        "description": "Token de instalación de GitHub App.",
        "severity":    "critical",
        "pattern":     _r(r"ghs_[0-9A-Za-z]{36}"),
        "category":    "tokens",
    },

    # ── Slack ─────────────────────────────────────────────────────────────────
    {
        "id":          "SLACK_BOT_TOKEN",
        "name":        "Slack Bot Token",
        "description": "Token de bot de Slack con acceso a workspaces.",
        "severity":    "high",
        "pattern":     _r(r"xoxb-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}"),
        "category":    "tokens",
    },
    {
        "id":          "SLACK_USER_TOKEN",
        "name":        "Slack User Token",
        "description": "Token de usuario de Slack.",
        "severity":    "high",
        "pattern":     _r(r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{32}"),
        "category":    "tokens",
    },
    {
        "id":          "SLACK_WEBHOOK",
        "name":        "Slack Webhook URL",
        "description": "URL de webhook de Slack que permite enviar mensajes.",
        "severity":    "medium",
        "pattern":     _r(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
        "category":    "tokens",
    },

    # ── Stripe ────────────────────────────────────────────────────────────────
    {
        "id":          "STRIPE_SECRET_KEY",
        "name":        "Stripe Secret Key",
        "description": "Clave secreta de Stripe con acceso a pagos.",
        "severity":    "critical",
        "pattern":     _r(r"sk_live_[0-9A-Za-z]{24,}"),
        "category":    "payment",
    },
    {
        "id":          "STRIPE_RESTRICTED_KEY",
        "name":        "Stripe Restricted Key",
        "description": "Clave restringida de Stripe.",
        "severity":    "high",
        "pattern":     _r(r"rk_live_[0-9A-Za-z]{24,}"),
        "category":    "payment",
    },

    # ── Twilio ────────────────────────────────────────────────────────────────
    {
        "id":          "TWILIO_ACCOUNT_SID",
        "name":        "Twilio Account SID",
        "description": "SID de cuenta de Twilio.",
        "severity":    "medium",
        "pattern":     _r(r"AC[0-9a-fA-F]{32}"),
        "category":    "tokens",
    },
    {
        "id":          "TWILIO_AUTH_TOKEN",
        "name":        "Twilio Auth Token",
        "description": "Token de autenticación de Twilio.",
        "severity":    "high",
        "pattern":     _r(r"(?i)twilio[^a-z0-9]*auth[^a-z0-9]*token[\s\"'`]*[:=][\s\"'`]*([0-9a-f]{32})"),
        "category":    "tokens",
    },

    # ── SendGrid ──────────────────────────────────────────────────────────────
    {
        "id":          "SENDGRID_API_KEY",
        "name":        "SendGrid API Key",
        "description": "Clave de API de SendGrid para envío de emails.",
        "severity":    "high",
        "pattern":     _r(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
        "category":    "tokens",
    },

    # ── Mailgun ───────────────────────────────────────────────────────────────
    {
        "id":          "MAILGUN_API_KEY",
        "name":        "Mailgun API Key",
        "description": "Clave de API de Mailgun.",
        "severity":    "high",
        "pattern":     _r(r"key-[0-9a-zA-Z]{32}"),
        "category":    "tokens",
    },

    # ── Azure ─────────────────────────────────────────────────────────────────
    {
        "id":          "AZURE_CLIENT_SECRET",
        "name":        "Azure Client Secret",
        "description": "Secreto de cliente de aplicación Azure AD.",
        "severity":    "critical",
        "pattern":     _r(r"(?i)azure[_\-\s]?client[_\-\s]?secret[\s\"'`]*[:=][\s\"'`]*([0-9A-Za-z~!@#$%^&*\-_+=]{34,64})"),
        "category":    "cloud_credentials",
    },
    {
        "id":          "AZURE_STORAGE_KEY",
        "name":        "Azure Storage Account Key",
        "description": "Clave de cuenta de Azure Storage.",
        "severity":    "critical",
        "pattern":     _r(r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
        "category":    "cloud_credentials",
    },

    # ── Heroku ────────────────────────────────────────────────────────────────
    {
        "id":          "HEROKU_API_KEY",
        "name":        "Heroku API Key",
        "description": "Clave de API de Heroku.",
        "severity":    "high",
        "pattern":     _r(r"(?i)heroku[^a-z0-9]*api[^a-z0-9]*key[\s\"'`]*[:=][\s\"'`]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
        "category":    "tokens",
    },

    # ── Credenciales hardcodeadas genéricas ───────────────────────────────────
    {
        "id":          "HARDCODED_PASSWORD",
        "name":        "Contraseña Hardcodeada",
        "description": "Contraseña directamente en el código fuente.",
        "severity":    "high",
        "pattern":     _r(
            r'(?i)(password|passwd|pwd|secret|pass)\s*[=:]\s*["\'](?!.*\{)[^\'"]{6,}'
        ),
        "category":    "credentials",
    },
    {
        "id":          "HARDCODED_USERNAME_PASSWORD",
        "name":        "Usuario:Contraseña en URL",
        "description": "Credenciales embebidas en una URL de conexión.",
        "severity":    "high",
        "pattern":     _r(r"[a-zA-Z]+://[^@\s]+:[^@\s]+@[a-zA-Z0-9\-\.]+"),
        "category":    "credentials",
    },
    {
        "id":          "GENERIC_API_KEY",
        "name":        "API Key Genérica",
        "description": "Posible API key detectada por nombre de variable.",
        "severity":    "medium",
        "pattern":     _r(
            r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|client[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9\-_\.]{16,})["\']'
        ),
        "category":    "credentials",
    },
    {
        "id":          "BEARER_TOKEN",
        "name":        "Bearer Token Hardcodeado",
        "description": "Token Bearer hardcodeado en código.",
        "severity":    "medium",
        "pattern":     _r(r'(?i)authorization\s*[=:]\s*["\']?bearer\s+([A-Za-z0-9\-_\.=+/]{20,})["\']?'),
        "category":    "tokens",
    },

    # ── Claves privadas / certificados ────────────────────────────────────────
    {
        "id":          "PRIVATE_KEY_RSA",
        "name":        "Clave Privada RSA",
        "description": "Clave privada RSA en formato PEM.",
        "severity":    "critical",
        "pattern":     _r(r"-----BEGIN RSA PRIVATE KEY-----"),
        "category":    "private_keys",
    },
    {
        "id":          "PRIVATE_KEY_EC",
        "name":        "Clave Privada EC",
        "description": "Clave privada de curva elíptica.",
        "severity":    "critical",
        "pattern":     _r(r"-----BEGIN EC PRIVATE KEY-----"),
        "category":    "private_keys",
    },
    {
        "id":          "PRIVATE_KEY_GENERIC",
        "name":        "Clave Privada Genérica",
        "description": "Clave privada en formato PEM.",
        "severity":    "critical",
        "pattern":     _r(r"-----BEGIN (?:OPENSSH|DSA|PRIVATE) (?:PRIVATE )?KEY-----"),
        "category":    "private_keys",
    },
    {
        "id":          "PGP_PRIVATE_KEY",
        "name":        "Clave PGP Privada",
        "description": "Clave privada PGP/GPG.",
        "severity":    "critical",
        "pattern":     _r(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "category":    "private_keys",
    },

    # ── Bases de datos ────────────────────────────────────────────────────────
    {
        "id":          "DATABASE_URL",
        "name":        "URL de Base de Datos con Credenciales",
        "description": "Cadena de conexión a base de datos con usuario y contraseña.",
        "severity":    "critical",
        "pattern":     _r(
            r"(?i)(postgres|mysql|mongodb|redis|mariadb|mssql)(\+[a-z]+)?://[^:@\s]+:[^@\s]+@[a-zA-Z0-9\-\.\:]+/[^\s]+"
        ),
        "category":    "credentials",
    },
    {
        "id":          "MONGO_CONNECTION",
        "name":        "MongoDB Connection String",
        "description": "Cadena de conexión MongoDB (posiblemente con credenciales).",
        "severity":    "high",
        "pattern":     _r(r"mongodb(\+srv)?://[^\s\"']+"),
        "category":    "credentials",
    },

    # ── JWT ───────────────────────────────────────────────────────────────────
    {
        "id":          "JWT_SECRET",
        "name":        "JWT Secret Hardcodeado",
        "description": "Secreto para firmar tokens JWT expuesto en código.",
        "severity":    "high",
        "pattern":     _r(
            r'(?i)jwt[_\-]?secret\s*[=:]\s*["\']([A-Za-z0-9!@#$%^&*\-_+=]{8,})["\']'
        ),
        "category":    "credentials",
    },

    # ── NPM / PyPI ────────────────────────────────────────────────────────────
    {
        "id":          "NPM_TOKEN",
        "name":        "NPM Access Token",
        "description": "Token de acceso de npm.",
        "severity":    "high",
        "pattern":     _r(r"npm_[A-Za-z0-9]{36}"),
        "category":    "tokens",
    },

    # ── Docker Hub ────────────────────────────────────────────────────────────
    {
        "id":          "DOCKERHUB_CRED",
        "name":        "Docker Hub Credenciales",
        "description": "Posibles credenciales de Docker Hub en archivo de configuración.",
        "severity":    "medium",
        "pattern":     _r(r'"auths"\s*:\s*\{[^}]*"https://index\.docker\.io/v1/"'),
        "category":    "credentials",
    },

    # ── SSH / Telnet ──────────────────────────────────────────────────────────
    {
        "id":          "SSH_PASSWORD",
        "name":        "Contraseña SSH en Script",
        "description": "Contraseña SSH expuesta en script de automatización.",
        "severity":    "high",
        "pattern":     _r(r"(?i)sshpass\s+-p\s+['\"]?([^\s'\"]+)"),
        "category":    "credentials",
    },
]


# ── Índice por ID para búsqueda rápida ────────────────────────────────────────
RULES_BY_ID: dict[str, Rule] = {r["id"]: r for r in RULES}

# ── Reglas agrupadas por severidad ────────────────────────────────────────────
RULES_BY_SEVERITY: dict[str, list[Rule]] = {
    sev: [r for r in RULES if r["severity"] == sev]
    for sev in ("critical", "high", "medium", "low")
}
