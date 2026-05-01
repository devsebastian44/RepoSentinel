#!/usr/bin/env bash
# scripts/setup.sh — Instalación rápida del entorno de desarrollo

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   GitHub Security Scanner — Setup        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Python 3.9+ requerido ────────────────────────────────────────────────────
PYTHON_CMD=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        version=$("$cmd" -c "import sys; print(sys.version_info[:2])")
        if [[ "$version" > "(3, 8)" ]]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [[ -z "$PYTHON_CMD" ]]; then
    echo "❌ Se requiere Python 3.9 o superior."
    exit 1
fi

echo "✅ Python encontrado: $PYTHON_CMD ($("$PYTHON_CMD" --version))"

# ── Crear virtualenv ─────────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    echo "📦 Creando entorno virtual en ${VENV_DIR}…"
    "$PYTHON_CMD" -m venv "$VENV_DIR"
else
    echo "📦 Entorno virtual ya existe."
fi

# ── Activar y actualizar pip ──────────────────────────────────────────────────
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip --quiet

# ── Instalar dependencias ─────────────────────────────────────────────────────
echo "📥 Instalando dependencias…"
pip install -r "${PROJECT_DIR}/requirements.txt" --quiet
echo "✅ Dependencias instaladas."

# ── Crear .env si no existe ───────────────────────────────────────────────────
if [[ ! -f "${PROJECT_DIR}/.env" ]]; then
    cp "${PROJECT_DIR}/.env.example" "${PROJECT_DIR}/.env"
    echo ""
    echo "⚠️  Se creó un archivo .env desde .env.example."
    echo "   👉 Edita '${PROJECT_DIR}/.env' y añade tu GITHUB_TOKEN."
else
    echo "✅ Archivo .env ya existe."
fi

# ── Verificar token ───────────────────────────────────────────────────────────
if grep -q "ghp_YOUR_TOKEN_HERE" "${PROJECT_DIR}/.env" 2>/dev/null; then
    echo ""
    echo "⚠️  GITHUB_TOKEN no configurado en .env"
    echo "   Genera un token en: https://github.com/settings/tokens"
fi

# ── Crear directorios necesarios ──────────────────────────────────────────────
mkdir -p "${PROJECT_DIR}/output" "${PROJECT_DIR}/logs"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   ✅ Setup completado.                               ║"
echo "║                                                      ║"
echo "║   Para empezar:                                      ║"
echo "║     source .venv/bin/activate                        ║"
echo "║     python main.py keyword 'aws secret' -n 5         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
