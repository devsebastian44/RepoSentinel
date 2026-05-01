# RepoSentinel

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat&logo=python)
![Docker](https://img.shields.io/badge/Docker-Multi--Stage-2496ED?style=flat&logo=docker)
![Security](https://img.shields.io/badge/Purpose-Security_Scanning-critical?style=flat&logo=shieldsdotio)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-CI%2FCD-2088FF?style=flat&logo=github-actions&logoColor=white)
![GitHub API](https://img.shields.io/badge/GitHub_API-REST_v3-181717?style=flat&logo=github)

---

## 🧠 Overview

RepoSentinel es una herramienta de ciberseguridad ofensiva-defensiva orientada a la auditoría automatizada de repositorios públicos de GitHub. Escrita en Python 3.12, opera como una CLI modular que consume la GitHub REST API v3 para descubrir, inspeccionar y puntuar repositorios en busca de secretos expuestos, credenciales hardcodeadas y archivos sensibles filtrados accidentalmente.

El proyecto se organiza bajo un motor de reglas extensible mediante expresiones regulares y archivos YAML personalizables, soporta escaneo concurrente con `ThreadPoolExecutor` y genera reportes duales en formatos Markdown y JSON. Este proyecto parece diseñado para escenarios de auditoría de seguridad responsable, pentesting autorizado, investigación académica y revisión interna de superficies de exposición en plataformas de control de versiones.

> ⚠️ **Ethical Disclaimer**: This project is for educational and ethical cybersecurity purposes only. Its use without authorization over third-party repositories or infrastructures may violate GitHub's Terms of Service and applicable laws. Always use it responsibly.

---

## ⚙️ Features

- **CLI completo con subcomandos**: escaneo por URL directa, búsqueda por keyword, usuario/organización y repositorios trending.
- **Motor de detección con 35+ reglas regex** cubriendo proveedores como AWS, Google Cloud, GitHub, Stripe, Twilio, SendGrid, Azure, Heroku, Slack y claves privadas (RSA, SSH, PGP).
- **Detección de 30+ patrones de archivos sensibles** por nombre y extensión: `.env`, `id_rsa`, `*.pem`, `kubeconfig`, `terraform.tfstate`, `.aws/credentials`, dumps SQL, y más.
- **Reglas personalizadas en YAML** cargadas automáticamente desde `rules/custom_rules.yaml`, sin modificar el código fuente.
- **Escaneo paralelo** mediante `ThreadPoolExecutor` configurable via `MAX_WORKERS`.
- **Gestión inteligente de rate-limit** con back-off exponencial y detección automática del límite de la GitHub API (hasta 5.000 req/h con token).
- **Sistema de Security Score 0–100** con calificación A–F por repositorio, basado en severidad ponderada de hallazgos.
- **Reportes duales**: Markdown legible para humanos y JSON estructurado para integración en pipelines o dashboards.
- **Logging avanzado**: salida en consola con colores (Windows via `colorama`) y archivo rotativo diario.
- **Containerización completa** con Dockerfile multi-stage (builder + runner) bajo usuario no-root `scanner`.
- **Integración de herramientas de seguridad de desarrollo**: `bandit` (SAST), `safety` / `pip-audit` (SCA), `mypy` (tipado estático), `ruff` (linting y formato).
- **Hooks de pre-commit** configurados mediante `.pre-commit-config.yaml`.

---

## 🛠️ Tech Stack

| Categoría | Tecnología / Librería |
|---|---|
| Lenguaje | Python 3.12 |
| HTTP Client | `requests` ≥ 2.31 |
| Variables de entorno | `python-dotenv` |
| Reglas custom | `PyYAML` |
| CLI coloreado | `colorama` (Windows) |
| Seguridad HTTP | `urllib3` ≥ 2.6 |
| Linting / Formato | `ruff`, `black`, `flake8` |
| Análisis estático | `mypy` |
| SAST | `bandit` |
| SCA | `safety`, `pip-audit` |
| Testing | `pytest` + `pytest-cov` |
| Pre-commit hooks | `pre-commit` |
| Contenerización | Docker (multi-stage, Python 3.12-slim) |
| Automatización | `Makefile` |
| Empaquetado | `setuptools` + `pyproject.toml` |

---

## 📦 Installation

### Prerrequisitos

- Python `>=3.11` (recomendado 3.12)
- Token de acceso personal de GitHub con permiso `public_repo` (solo lectura)
- Docker (opcional, para ejecución containerizada)

### 🐧 Linux / macOS

```bash
# 1. Clonar el repositorio
git clone https://github.com/devsebastian44/RepoSentinel.git
cd RepoSentinel

# 2. Crear entorno virtual e instalar dependencias de producción
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Alternativamente, instalación completa con extras de desarrollo
pip install -e ".[dev,security]"

# 4. Configurar variables de entorno
cp .env.example .env
# Editar .env y añadir GITHUB_TOKEN
```

### 🪟 Windows

```powershell
git clone https://github.com/devsebastian44/RepoSentinel.git
cd RepoSentinel

python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt

Copy-Item .env.example .env
# Editar .env con tu GITHUB_TOKEN
```

### 🐳 Docker

```bash
# Construir imagen multi-stage
docker build -t repo-sentinel .

# Ejecutar con variables de entorno
docker run --rm -it --env-file .env repo-sentinel --help
```

### ⚡ Con Makefile (recomendado para desarrollo)

```bash
make install        # Producción
make install-dev    # Desarrollo completo + pre-commit
make dev-setup      # Setup completo del entorno de desarrollo
```

---

## ▶️ Usage

> Todas las ejecuciones apuntan directamente a `python src/main.py` por la arquitectura segregada del proyecto.

### Escaneo por URL directa

```bash
python src/main.py url https://github.com/owner/repository
python src/main.py url owner/repo
```

### Búsqueda por keyword

```bash
python src/main.py keyword "aws secret key" --max-repos 5
python src/main.py keyword "firebase" --language javascript --max-repos 10
python src/main.py keyword "django" --format json -n 3
```

### Por usuario u organización

```bash
python src/main.py user octocat --max-repos 10
python src/main.py user microsoft --max-repos 20 --workers 8
```

### Repositorios trending

```bash
python src/main.py trending --max-repos 10
python src/main.py trending --language python --max-repos 15 --workers 8
```

### Verificar rate-limit de la API

```bash
python src/main.py rate-limit
```

### Opciones globales combinadas

```bash
python src/main.py keyword "stripe" \
  --max-repos 5 \
  --workers 3 \
  --format md json \
  --output-dir ./mis_reportes \
  --token ghp_XXXX \
  --no-banner
```

### Comandos Makefile útiles

```bash
make run            # Ejecutar scanner con --help
make test           # Tests con cobertura
make lint           # Ruff + mypy
make security       # pip-audit + bandit
make docker-build   # Construir imagen Docker
make docker-run     # Ejecutar contenedor con .env
make clean          # Limpiar caches y artefactos de build
```

---

## 📁 Project Structure

```
RepoSentinel/
│
├── src/                        # Código fuente principal
│   ├── main.py                 # CLI (argparse): subcomandos, resumen en consola
│   ├── config.py               # Configuración base cargada desde .env
│   ├── core/                   # Módulos core del sistema
│   │   ├── github_api.py       # Cliente GitHub REST v3 (rate-limit, paginado, raw files)
│   │   ├── scanner.py          # Motor de escaneo concurrente (ThreadPoolExecutor)
│   │   └── logger.py           # Logger con colores y rotación de archivos
│   ├── rules/                  # Motor de reglas de detección
│   │   ├── patterns.py         # 35+ regex por severidad (AWS, GCP, GitHub, Stripe...)
│   │   ├── sensitive_files.py  # 30+ patrones de archivos por nombre/extensión
│   │   └── custom_rules.yaml   # Reglas personalizadas del usuario (cargadas automáticamente)
│   └── reports/                # Motores de generación de reportes
│       ├── reporter.py         # Orquestador de reportes
│       ├── markdown_report.py  # Generación de report .md
│       └── json_report.py      # Generación de report .json
│
├── .env.example                # Plantilla de variables de entorno (sin secretos reales)
├── .pre-commit-config.yaml     # Hooks de pre-commit (linting, seguridad)
├── Dockerfile                  # Imagen multi-stage Python 3.12-slim, usuario no-root
├── Makefile                    # Automatización: install, test, lint, security, docker
├── pyproject.toml              # Metadatos del paquete, ruff, mypy, pytest, coverage
├── requirements.txt            # Dependencias de producción fijadas
└── LICENSE                     # Licencia MIT
```

---

## 🔐 Security

Este proyecto está diseñado con un enfoque de **seguridad por capas**, tanto en su implementación interna como en la forma en que audita repositorios externos.

### Seguridad interna de la herramienta

- **Usuario no-root en Docker**: el contenedor crea y ejecuta bajo el usuario `scanner` (UID dedicado), sin privilegios de root.
- **Dockerfile multi-stage**: la imagen final no contiene compiladores ni herramientas de build, reduciendo la superficie de ataque.
- **SAST con Bandit**: análisis estático del código Python en busca de patrones inseguros, ejecutado en CI y disponible via `make security`.
- **SCA con safety/pip-audit**: verificación de dependencias contra bases de datos de vulnerabilidades conocidas (CVEs).
- **Análisis de tipo estricto con mypy**: configurado en modo estricto (`disallow_untyped_defs`, `warn_return_any`, `strict_equality`), reduciendo la probabilidad de errores de runtime.
- **Pre-commit hooks**: controles automáticos antes de cada commit para prevenir regresiones de calidad o seguridad.
- **Token con permisos mínimos**: el `.env.example` documenta explícitamente que solo se requiere permiso `public_repo` (lectura), siguiendo el principio de mínimo privilegio.

### Uso ético y responsable

Esta herramienta opera exclusivamente sobre repositorios **públicos** mediante la GitHub API oficial. Está concebida para:

- ✅ Auditar tus propios repositorios o los de tu organización.
- ✅ Investigación de seguridad con enfoque de **responsible disclosure**.
- ✅ Aprendizaje y laboratorio de ciberseguridad.
- ✅ Pentesting con autorización explícita del propietario.

No está diseñada para explotar vulnerabilidades encontradas en repositorios ajenos. Si se detecta un secreto expuesto en un repositorio de terceros, la práctica correcta es notificar al propietario responsablemente. Muchas plataformas cuentan con programas de bug bounty para este fin.

> **El uso de esta herramienta es responsabilidad exclusiva del usuario.**


## 🚀 Roadmap

Basado en el análisis de la arquitectura actual y las dependencias detectadas en el código:

- [ ] **Soporte para repositorios privados** con tokens de alcance ampliado y gestión de permisos.
- [ ] **Análisis de historial de git**: escaneo de commits pasados donde el secreto fue removido pero aún existe en el historial.
- [ ] **Exportación a SARIF** (formato estándar de GitHub Code Scanning / OASIS).
- [ ] **Modo watch/monitor**: detección continua de nuevos commits o repositorios en tiempo real.
- [ ] **Verificación de validez del secreto**: comprobar si las credenciales detectadas siguen activas (requiere manejo ético cuidadoso).
- [ ] **Integración con GitLab y Bitbucket** bajo la misma arquitectura modular de clientes API.
- [ ] **Dashboard web con FastAPI/Flask** para visualizar y filtrar reportes desde el navegador.
- [ ] **Notificaciones por webhooks** (Slack/email) cuando se detectan hallazgos de severidad crítica.
- [ ] **Motor ML/NLP** para reducción de falsos positivos mediante análisis semántico de contexto.
- [ ] **Base de datos histórica** (SQLite/PostgreSQL) para tracking de hallazgos a lo largo del tiempo.
- [ ] **API REST propia** para integración nativa en pipelines CI/CD de terceros.
- [ ] **GitHub Action oficial** para auditoría automática en workflows de repositorios.
- [ ] **Plugin pre-commit** para detección local antes de cada push.

---

## 🤝 Contributing

¡Las contribuciones son bienvenidas! Si quieres mejorar RepoSentinel, sigue estos pasos:

1.  **Fork** el repositorio.
2.  Crea una nueva rama para tu funcionalidad (`git checkout -b feature/amazing-feature`).
3.  Realiza tus cambios y asegúrate de que los tests pasen (`make test`).
4.  Haz commit de tus cambios siguiendo **Conventional Commits**.
5.  Haz **Push** a la rama (`git push origin feature/amazing-feature`).
6.  Abre un **Pull Request** detallando tus cambios.

### Estilo de Commit

Este proyecto utiliza [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` para nuevas funcionalidades.
- `fix:` para corrección de errores.
- `docs:` para cambios en documentación.
- `test:` para añadir o modificar tests.
- `refactor:` para cambios en el código que no añaden funciones ni arreglan bugs.

---

## 📄 License

Este proyecto está bajo la licencia **MIT**.

> Licencia detectada directamente desde el archivo `LICENSE` en la raíz del repositorio y confirmada en los clasificadores de `pyproject.toml` (`License :: OSI Approved :: MIT License`).

---

## 👨‍💻 Author

**Sebastian Zhunaula** — [@devsebastian44](https://github.com/devsebastian44)

Desarrollador y analista de seguridad con enfoque en herramientas de auditoría, arquitecturas DevSecOps y automatización de laboratorios de ciberseguridad.