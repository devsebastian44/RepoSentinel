"""
config.py — Configuración global del GitHub Security Scanner.
Centraliza tokens, límites de API, rutas y ajustes de comportamiento.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Rutas base ────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
RULES_DIR   = BASE_DIR / "rules"
REPORTS_DIR = BASE_DIR / "output"
LOGS_DIR    = BASE_DIR / "logs"

for _d in (REPORTS_DIR, LOGS_DIR):
    _d.mkdir(exist_ok=True)

# ── GitHub API ────────────────────────────────────────────────────────────────
GITHUB_TOKEN   = os.getenv("GITHUB_TOKEN", "")
GITHUB_API_URL = "https://api.github.com"
GITHUB_RAW_URL = "https://raw.githubusercontent.com"

# Número máximo de repositorios a procesar por búsqueda
MAX_REPOS = int(os.getenv("MAX_REPOS", 10))

# Número máximo de archivos a analizar por repositorio
MAX_FILES_PER_REPO = int(os.getenv("MAX_FILES_PER_REPO", 100))

# Tamaño máximo de archivo a descargar (bytes) — evita archivos binarios enormes
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", 500_000))   # 500 KB

# ── Concurrencia ──────────────────────────────────────────────────────────────
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 5))

# ── Rate limiting ─────────────────────────────────────────────────────────────
# Pausa (segundos) cuando quedan pocos requests antes del reset de la API
RATE_LIMIT_PAUSE   = float(os.getenv("RATE_LIMIT_PAUSE", 2.0))
RATE_LIMIT_MIN_REM = int(os.getenv("RATE_LIMIT_MIN_REM", 10))   # requests mínimos

# ── Scoring ───────────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high":     20,
    "medium":   10,
    "low":       3,
}

SCORE_THRESHOLDS = {
    "A": 90,   # Excelente
    "B": 70,   # Bueno
    "C": 50,   # Regular
    "D": 30,   # Malo
    "F": 0,    # Crítico
}

# ── Extensiones a ignorar (binarios, multimedia, etc.) ────────────────────────
IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pyc", ".pyo", "__pycache__",
    ".lock", ".sum",
}

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL  = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE   = "%Y-%m-%d %H:%M:%S"
