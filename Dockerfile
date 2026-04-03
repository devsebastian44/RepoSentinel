# Dockerfile - RepoSentinel GitHub Security Scanner
# Versión optimizada para producción (Senior DevOps Pattern)

# Etapa 1: Construcción
FROM python:3.12-slim AS builder

WORKDIR /app

# Instalar dependencias de compilación mínimas si fueran necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias en el espacio de usuario para facilitar la copia
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Etapa 2: Imagen Final
FROM python:3.12-slim

LABEL maintainer="RepoSentinel Team <contact@reposentinel.dev>"
LABEL description="GitHub Security Scanner - isolated environment"

WORKDIR /app

# Crear usuario no-root por seguridad
RUN groupadd -r scanner && useradd -r -g scanner scanner

# Copiar solo las dependencias instaladas y el código fuente
COPY --from=builder /root/.local /home/scanner/.local
COPY . .

# Configurar entorno
ENV PATH=/home/scanner/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Ajustar permisos
RUN chown -R scanner:scanner /app
USER scanner

# Entrada principal
ENTRYPOINT ["python", "src/main.py"]
CMD ["--help"]
