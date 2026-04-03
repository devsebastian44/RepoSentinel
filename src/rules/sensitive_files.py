"""
rules/sensitive_files.py — Reglas para detectar archivos sensibles por nombre/extensión.

Cada entrada define un patrón de nombre de archivo (glob-style regex) con su
severidad y descripción para el reporte.
"""

from __future__ import annotations

import re
from typing import TypedDict


class SensitiveFileRule(TypedDict):
    id: str
    name: str
    description: str
    severity: str
    pattern: re.Pattern


def _r(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


SENSITIVE_FILE_RULES: list[SensitiveFileRule] = [
    # ── Variables de entorno ──────────────────────────────────────────────────
    {
        "id": "ENV_FILE",
        "name": "Archivo .env",
        "description": "Archivo de variables de entorno que suele contener secretos.",
        "severity": "critical",
        "pattern": _r(r"(^|/)\.env(\.[a-z]+)?$"),
    },
    {
        "id": "ENV_BACKUP",
        "name": "Backup de archivo .env",
        "description": "Copia de seguridad de archivo .env, frecuentemente accesible.",
        "severity": "critical",
        "pattern": _r(r"(^|/)\.env\.(bak|old|backup|copy|save|1|2)$"),
    },
    # ── Claves SSH ────────────────────────────────────────────────────────────
    {
        "id": "SSH_KEY_FILE",
        "name": "Clave SSH Privada",
        "description": "Clave privada SSH que permite autenticación sin contraseña.",
        "severity": "critical",
        "pattern": _r(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519|id_xmss)(\.pem)?$"),
    },
    {
        "id": "SSH_CONFIG",
        "name": "Configuración SSH",
        "description": "Archivo de configuración SSH que puede revelar hosts y usuarios.",
        "severity": "medium",
        "pattern": _r(r"(^|/)\.ssh/config$"),
    },
    # ── Certificados y claves PEM ─────────────────────────────────────────────
    {
        "id": "PEM_KEY",
        "name": "Archivo de Clave PEM",
        "description": "Archivo de clave privada en formato PEM.",
        "severity": "critical",
        "pattern": _r(r"\.(pem|key|p12|pfx|jks|keystore)$"),
    },
    {
        "id": "PGP_KEY",
        "name": "Clave PGP/GPG",
        "description": "Clave privada PGP o GPG.",
        "severity": "critical",
        "pattern": _r(r"\.(pgp|gpg|asc)$"),
    },
    # ── Configuraciones de servicios ──────────────────────────────────────────
    {
        "id": "AWS_CREDENTIALS",
        "name": "Credenciales AWS",
        "description": "Archivo de credenciales de AWS CLI.",
        "severity": "critical",
        "pattern": _r(r"(^|/)(\.aws/credentials|aws_credentials)$"),
    },
    {
        "id": "KUBECONFIG",
        "name": "Kubeconfig de Kubernetes",
        "description": "Configuración de acceso a clúster Kubernetes.",
        "severity": "critical",
        "pattern": _r(r"(^|/)kubeconfig(\.yml|\.yaml)?$"),
    },
    {
        "id": "DOCKER_CONFIG",
        "name": "Configuración de Docker",
        "description": "Configuración de Docker con posibles credenciales de registros.",
        "severity": "high",
        "pattern": _r(r"(^|/)\.docker/config\.json$"),
    },
    {
        "id": "NPMRC",
        "name": "Archivo .npmrc",
        "description": "Configuración de npm con posibles tokens de acceso.",
        "severity": "high",
        "pattern": _r(r"(^|/)\.npmrc$"),
    },
    {
        "id": "PYPIRC",
        "name": "Archivo .pypirc",
        "description": "Configuración de PyPI con posibles credenciales.",
        "severity": "high",
        "pattern": _r(r"(^|/)\.pypirc$"),
    },
    {
        "id": "NETRC",
        "name": "Archivo .netrc",
        "description": "Archivo de credenciales de red (.netrc) con usuario/contraseña.",
        "severity": "critical",
        "pattern": _r(r"(^|/)\.netrc$"),
    },
    {
        "id": "GIT_CREDENTIALS",
        "name": "Credenciales de Git",
        "description": "Archivo de credenciales almacenadas de git.",
        "severity": "high",
        "pattern": _r(r"(^|/)\.git-credentials$"),
    },
    # ── Configuraciones de aplicación ─────────────────────────────────────────
    {
        "id": "SETTINGS_JSON",
        "name": "settings.json / config.json",
        "description": "Archivos de configuración que pueden exponer secretos.",
        "severity": "medium",
        "pattern": _r(
            r"(^|/)(settings|config|configuration|app\.config|web\.config)\.(json|yaml|yml|xml|ini|toml)$"
        ),
    },
    {
        "id": "DATABASE_DUMP",
        "name": "Dump de Base de Datos",
        "description": "Volcado de base de datos con posible información sensible.",
        "severity": "critical",
        "pattern": _r(r"\.(sql|dump|db|sqlite|sqlite3|mdb|accdb)$"),
    },
    {
        "id": "LOG_FILE",
        "name": "Archivos de Log",
        "description": "Archivos de log que pueden contener información sensible.",
        "severity": "low",
        "pattern": _r(r"\.(log|logs)$"),
    },
    {
        "id": "HTPASSWD",
        "name": "Archivo htpasswd",
        "description": "Archivo de credenciales de Apache.",
        "severity": "high",
        "pattern": _r(r"(^|/)\.htpasswd$"),
    },
    {
        "id": "HTACCESS",
        "name": "Archivo .htaccess",
        "description": "Configuración de Apache que puede revelar estructura interna.",
        "severity": "low",
        "pattern": _r(r"(^|/)\.htaccess$"),
    },
    {
        "id": "SHADOW_PASSWD",
        "name": "Archivos shadow/passwd",
        "description": "Archivos de contraseñas del sistema operativo.",
        "severity": "critical",
        "pattern": _r(r"(^|/)(shadow|passwd|master\.passwd)$"),
    },
    # ── Secretos de CI/CD ─────────────────────────────────────────────────────
    {
        "id": "TRAVIS_CONFIG",
        "name": "Configuración Travis CI",
        "description": "Archivo de Travis CI que puede contener secretos encriptados.",
        "severity": "low",
        "pattern": _r(r"(^|/)\.travis\.yml$"),
    },
    {
        "id": "JENKINS_CREDS",
        "name": "Credenciales Jenkins",
        "description": "Archivo de credenciales de Jenkins.",
        "severity": "high",
        "pattern": _r(r"(^|/)credentials\.xml$"),
    },
    # ── Backups y archivos temporales ─────────────────────────────────────────
    {
        "id": "BACKUP_FILE",
        "name": "Archivo de Backup",
        "description": "Archivo de respaldo que puede contener datos sensibles.",
        "severity": "medium",
        "pattern": _r(r"\.(bak|backup|old|orig|save|copy|temp|tmp)$"),
    },
    {
        "id": "ANDROID_KEYSTORE",
        "name": "Android Keystore",
        "description": "Keystore de Android con claves de firma de apps.",
        "severity": "high",
        "pattern": _r(r"\.(keystore|jks)$"),
    },
    {
        "id": "TERRAFORM_STATE",
        "name": "Terraform State File",
        "description": "Archivo de estado de Terraform con posible info sensible de infraestructura.",
        "severity": "high",
        "pattern": _r(r"(^|/)terraform\.tfstate(\.backup)?$"),
    },
    {
        "id": "TERRAFORM_VARS",
        "name": "Terraform Variables con Secretos",
        "description": "Archivo de variables de Terraform que puede contener secretos.",
        "severity": "medium",
        "pattern": _r(r"(^|/)terraform\.tfvars$"),
    },
    {
        "id": "ANSIBLE_VAULT",
        "name": "Ansible Vault",
        "description": "Archivo de Ansible Vault (verificar si está sin encriptar).",
        "severity": "medium",
        "pattern": _r(r"(^|/)vault\.(yml|yaml)$"),
    },
]


def match_sensitive_file(path: str) -> list[SensitiveFileRule]:
    """
    Comprueba si un path de archivo coincide con alguna regla de archivo sensible.

    Args:
        path: Ruta relativa del archivo dentro del repositorio.

    Returns:
        Lista de reglas que coinciden (puede ser más de una).
    """
    return [rule for rule in SENSITIVE_FILE_RULES if rule["pattern"].search(path)]
