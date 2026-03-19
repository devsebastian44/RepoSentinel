# 🔐 GitHub Security Scanner

> **Herramienta profesional de análisis de seguridad para repositorios públicos de GitHub.**  
> Detecta secretos expuestos, credenciales hardcodeadas y archivos sensibles mediante expresiones regulares y reglas personalizables.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Security](https://img.shields.io/badge/Purpose-Pentesting-red)

---

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Instalación](#-instalación)
- [Configuración](#-configuración)
- [Uso](#-uso)
- [Reglas de Detección](#-reglas-de-detección)
- [Reportes](#-reportes)
- [Sistema de Scoring](#-sistema-de-scoring)
- [Reglas Personalizadas](#-reglas-personalizadas)
- [Consideraciones Éticas y Legales](#-consideraciones-éticas-y-legales)
- [Ideas para Mejoras Futuras](#-ideas-para-mejoras-futuras)
- [Contribuir](#-contribuir)

---

## ✨ Características

| Característica | Descripción |
|---|---|
| 🔑 **Autenticación GitHub** | Soporte de token para aumentar el rate-limit (5000 req/h) |
| 🔍 **Búsqueda múltiple** | Por keyword, usuario/org o trending semanal |
| 🧠 **35+ reglas de detección** | AWS, Google, GitHub, Stripe, Slack, Azure, etc. |
| 📁 **Archivos sensibles** | 30+ patrones de nombre: .env, id_rsa, credentials, etc. |
| ⚙️ **Reglas personalizables** | Añade tus propias reglas en YAML sin tocar código |
| ⚡ **Concurrencia** | ThreadPoolExecutor para escanear múltiples repos en paralelo |
| 🛡️ **Rate-limit inteligente** | Detección automática + back-off exponencial |
| 📊 **Security Score** | Puntuación 0-100 + nota A-F por repositorio |
| 📄 **Reportes duales** | Markdown (legible) y JSON (integrable) |
| 🖥️ **CLI completo** | Subcomandos, flags, ayuda detallada |
| 📝 **Logging avanzado** | Consola con colores + archivo rotativo diario |

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                        main.py (CLI)                        │
│         argparse · subcomandos · resumen en consola         │
└──────────────────────┬──────────────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
┌─────────────┐  ┌──────────┐  ┌──────────────┐
│ github_api  │  │ scanner  │  │   reporter   │
│             │  │          │  │              │
│ • REST v3   │  │ • árbol  │  │ • Markdown   │
│ • rate-limit│  │ • filtro │  │ • JSON       │
│ • paginado  │  │ • threads│  │ • scoring    │
│ • raw files │  │ • scoring│  │ • badges     │
└─────────────┘  └────┬─────┘  └──────────────┘
                      │
            ┌─────────┴──────────┐
            ▼                    ▼
    ┌──────────────┐    ┌─────────────────┐
    │  patterns.py │    │sensitive_files.py│
    │              │    │                 │
    │ 35+ regex    │    │ 30+ file rules  │
    │ por severidad│    │ por nombre/ext  │
    └──────────────┘    └─────────────────┘
            │
    ┌───────┴──────────┐
    ▼                  ▼
┌──────────────┐  ┌──────────────┐
│patterns.py   │  │custom_rules  │
│(built-in)    │  │.yaml (user)  │
└──────────────┘  └──────────────┘
```

### Flujo de datos

```
Usuario
  │
  ▼ CLI args
main.py
  │
  ├──► GitHubClient.search_repos_*()
  │         │
  │         └──► [lista de repos]
  │
  ├──► RepositoryScanner.scan_repos()
  │         │
  │         ├──► get_file_tree()  ──► filtrar por extensión/nombre
  │         │
  │         ├──► match_sensitive_file()  ──► SensitiveFileHit[]
  │         │
  │         └──► get_file_content() ──► ContentAnalyzer.analyze()
  │                                           │
  │                                           └──► Finding[]
  │
  └──► ReportManager.generate_all()
            │
            ├──► report_YYYYMMDD_HHMMSS.md
            └──► report_YYYYMMDD_HHMMSS.json
```

---

## 📁 Estructura del Proyecto

```
github-security-scanner/
│
├── main.py                    # CLI principal (argparse)
├── config.py                  # Configuración global centralizada
├── requirements.txt           # Dependencias Python
├── .env.example               # Plantilla de variables de entorno
│
├── core/                      # Módulos principales
│   ├── __init__.py
│   ├── github_api.py          # Cliente REST de GitHub API v3
│   ├── scanner.py             # Motor de escaneo + threading
│   └── logger.py              # Sistema de logging (consola + archivo)
│
├── rules/                     # Reglas de detección
│   ├── __init__.py
│   ├── patterns.py            # 35+ reglas regex por proveedor/categoría
│   ├── sensitive_files.py     # 30+ patrones de archivos sensibles
│   └── custom_rules.yaml      # Reglas personalizables por el usuario
│
├── reports/                   # Motor de reportes
│   ├── __init__.py
│   └── reporter.py            # Generadores Markdown y JSON
│
├── output/                    # Reportes generados (gitignored)
├── logs/                      # Archivos de log diarios (gitignored)
│
└── scripts/
    └── setup.sh               # Script de instalación automática
```

---

## 🚀 Instalación

### Requisitos previos

- Python 3.9 o superior
- Token de acceso personal de GitHub ([generar aquí](https://github.com/settings/tokens))

### Instalación rápida

```bash
# 1. Clonar el repositorio
git clone https://github.com/tuusuario/github-security-scanner.git
cd github-security-scanner

# 2. Ejecutar el script de setup (crea venv + instala deps + crea .env)
bash scripts/setup.sh

# 3. Activar el entorno virtual
source .venv/bin/activate   # Linux/macOS
# o
.venv\Scripts\activate      # Windows
```

### Instalación manual

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Editar .env y añadir GITHUB_TOKEN
```

---

## ⚙️ Configuración

Edita el archivo `.env`:

```env
# OBLIGATORIO
GITHUB_TOKEN=ghp_tu_token_aqui

# Opcional (valores por defecto)
MAX_REPOS=10              # Repos máximos por búsqueda
MAX_FILES_PER_REPO=100    # Archivos máximos por repo
MAX_FILE_SIZE=500000      # Tamaño máx. de archivo (bytes)
MAX_WORKERS=5             # Hilos paralelos
RATE_LIMIT_PAUSE=2.0      # Pausa (s) cuando el rate-limit es bajo
LOG_LEVEL=INFO            # DEBUG | INFO | WARNING | ERROR
```

---

## 🖥️ Uso

### Escaneo por palabra clave

```bash
# Buscar repos que mencionen "aws secret key"
python main.py keyword "aws secret key" --max-repos 5

# Filtrar por lenguaje
python main.py keyword "firebase" --language javascript --max-repos 10

# Generar solo JSON
python main.py keyword "django" --format json -n 3
```

### Escaneo por usuario u organización

```bash
# Escanear repos públicos de un usuario
python main.py user octocat --max-repos 10

# Escanear repos de una organización
python main.py user microsoft --max-repos 20 --workers 8
```

### Repositorios Trending

```bash
# Top trending de la semana (todos los lenguajes)
python main.py trending --max-repos 10

# Trending de Python con 8 workers
python main.py trending --language python --max-repos 15 --workers 8
```

### Verificar rate-limit

```bash
python main.py rate-limit
```

### Opciones globales

```bash
python main.py keyword "stripe" \
    --max-repos 5 \          # Límite de repos
    --workers 3 \            # Threads paralelos
    --format md json \       # Formatos de reporte
    --output-dir ./mis_reportes \  # Directorio de salida
    --token ghp_XXXX \       # Token inline (alternativa a .env)
    --no-banner              # Sin banner ASCII
```

### Ayuda

```bash
python main.py --help
python main.py keyword --help
python main.py user --help
```

---

## 🔍 Reglas de Detección

### Secretos en contenido de archivos (35+ reglas)

| Proveedor | Reglas | Severidad |
|---|---|---|
| **AWS** | Access Key, Secret Key, Session Token | 🔴 Critical / 🟠 High |
| **Google Cloud** | API Key, OAuth Secret, Service Account, Firebase | 🔴 Critical / 🟠 High |
| **GitHub** | PAT Classic, PAT Fine-Grained, OAuth Token, App Token | 🔴 Critical |
| **Slack** | Bot Token, User Token, Webhook URL | 🟠 High / 🟡 Medium |
| **Stripe** | Secret Key, Restricted Key | 🔴 Critical / 🟠 High |
| **Twilio** | Account SID, Auth Token | 🟠 High / 🟡 Medium |
| **SendGrid** | API Key | 🟠 High |
| **Azure** | Client Secret, Storage Key | 🔴 Critical |
| **Heroku** | API Key | 🟠 High |
| **Bases de datos** | URL con credenciales, MongoDB Connection | 🔴 Critical / 🟠 High |
| **Genérico** | Passwords hardcoded, Bearer tokens, JWT secrets | 🟠 High / 🟡 Medium |
| **Claves privadas** | RSA, EC, OpenSSH, PGP | 🔴 Critical |
| **NPM** | Access Token | 🟠 High |

### Archivos sensibles por nombre (30+ reglas)

| Patrón | Descripción | Severidad |
|---|---|---|
| `.env`, `.env.*` | Variables de entorno | 🔴 Critical |
| `id_rsa`, `id_ed25519` | Claves SSH privadas | 🔴 Critical |
| `*.pem`, `*.key`, `*.p12` | Certificados y claves | 🔴 Critical |
| `.aws/credentials` | Credenciales AWS CLI | 🔴 Critical |
| `kubeconfig` | Acceso a Kubernetes | 🔴 Critical |
| `.netrc` | Credenciales de red | 🔴 Critical |
| `terraform.tfstate` | Estado de infraestructura | 🟠 High |
| `.npmrc`, `.pypirc` | Tokens de registros de paquetes | 🟠 High |
| `.docker/config.json` | Credenciales de registros Docker | 🟠 High |
| `*.sql`, `*.dump` | Volcados de base de datos | 🔴 Critical |
| `credentials.xml` | Credenciales de Jenkins | 🟠 High |

---

## 📊 Reportes

Todos los reportes se guardan en `output/` con timestamp:

### Markdown (`report_YYYYMMDD_HHMMSS.md`)

Incluye:
- Resumen ejecutivo con métricas globales
- Tabla de todos los repositorios con score y badge
- Sección detallada por repositorio:
  - Archivos sensibles detectados
  - Vulnerabilidades en contenido (archivo, línea, extracto censurado)
- Recomendaciones generales de seguridad

### JSON (`report_YYYYMMDD_HHMMSS.json`)

```json
{
  "meta": {
    "tool": "github-security-scanner",
    "version": "1.0.0",
    "generated_at": "2025-01-15T10:30:00+00:00",
    "repos_scanned": 5
  },
  "summary": {
    "total_issues": 23,
    "files_analyzed": 412,
    "severity_counts": { "critical": 3, "high": 8, "medium": 9, "low": 3 },
    "average_score": 61,
    "repos_with_critical": 2
  },
  "repositories": [
    {
      "repo": { "full_name": "user/repo", "url": "...", "stars": 142 },
      "score": { "value": 20, "grade": "D" },
      "findings": [...],
      "sensitive_files": [...]
    }
  ]
}
```

---

## 📈 Sistema de Scoring

Cada repositorio recibe un **Security Score** de 0 a 100:

```
Score = 100 - Σ(peso_severidad × cantidad_issues_de_esa_severidad)
```

| Severidad | Peso por issue |
|---|---|
| 🔴 Critical | -40 puntos |
| 🟠 High | -20 puntos |
| 🟡 Medium | -10 puntos |
| 🟢 Low | -3 puntos |

El score mínimo es 0 (nunca negativo).

### Tabla de notas

| Nota | Score mínimo | Interpretación |
|---|---|---|
| **A** | 90 | Excelente — Sin issues o sólo bajos |
| **B** | 70 | Bueno — Pocos issues menores |
| **C** | 50 | Regular — Issues medios/altos presentes |
| **D** | 30 | Malo — Múltiples vulnerabilidades graves |
| **F** | 0 | Crítico — Secretos expuestos confirmados |

---

## 🔧 Reglas Personalizadas

Añade tus propias reglas en `rules/custom_rules.yaml` sin modificar el código:

```yaml
rules:
  - id:          MI_TOKEN_INTERNO
    name:        Token de API Interna
    description: Token de acceso al sistema interno ACME Corp.
    severity:    critical        # critical | high | medium | low
    pattern:     'acme_[0-9a-f]{40}'
    category:    custom

  - id:          INTERNAL_DB
    name:        Conexión a BD Corporativa
    description: Cadena de conexión al servidor Oracle interno.
    severity:    critical
    pattern:     'jdbc:oracle://db\.corp\.acme\.com'
    category:    custom
```

Las reglas se cargan automáticamente en cada ejecución.

---

## ⚖️ Consideraciones Éticas y Legales

> ⚠️ **IMPORTANTE: Lee esto antes de usar esta herramienta.**

Esta herramienta está diseñada para:

- ✅ Auditar **tus propios repositorios** o de tu organización.
- ✅ **Investigación de seguridad** responsable (responsible disclosure).
- ✅ **Educación** y aprendizaje de ciberseguridad.
- ✅ **Pentesting** con autorización expresa del propietario.

**No está diseñada para:**

- ❌ Acceder sin autorización a datos de terceros.
- ❌ Explotar vulnerabilidades encontradas en repos ajenos.
- ❌ Violar los [Términos de Servicio de GitHub](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service).

Si encuentras un secreto expuesto en un repo ajeno, la práctica correcta es notificar al propietario de forma responsable (responsible disclosure). Muchas plataformas tienen programas de bug bounty.

**El uso de esta herramienta es responsabilidad exclusiva del usuario.**

---

## 🚀 Ideas para Mejoras Futuras

### Corto plazo
- [ ] **Soporte para repositorios privados** (con los permisos adecuados del token).
- [ ] **Análisis de historial de git** (commits pasados donde el secreto fue borrado).
- [ ] **Exportación a SARIF** (formato estándar de GitHub Code Scanning).
- [ ] **Modo watch**: monitoreo continuo de nuevos commits.

### Medio plazo
- [ ] **Integración con GitLab y Bitbucket** (misma arquitectura, diferente cliente API).
- [ ] **Dashboard web** con Flask/FastAPI para visualizar reportes en navegador.
- [ ] **Notificaciones** via Slack/email/webhook cuando se detectan críticos.
- [ ] **Verificación de validez**: comprobar si el secreto detectado sigue activo.
- [ ] **Plugin de pre-commit** para uso local en proyectos.

### Largo plazo
- [ ] **Motor ML/NLP** para detección de secretos con semántica (reducir falsos positivos).
- [ ] **Base de datos de resultados** (SQLite/PostgreSQL) para comparación histórica.
- [ ] **API REST propia** para integración en pipelines CI/CD.
- [ ] **Contenedor Docker** oficial.
- [ ] **GitHub Action** para integración nativa en workflows.
- [ ] **Soporte para Semgrep** como motor de análisis estático adicional.

---

## 🤝 Contribuir

Las contribuciones son bienvenidas. Por favor:

1. Haz fork del repositorio.
2. Crea una rama descriptiva: `git checkout -b feat/nueva-regla-azure`.
3. Haz commit de tus cambios con mensajes claros.
4. Abre un Pull Request con descripción detallada.

Para añadir nuevas reglas de detección, edita `rules/patterns.py` siguiendo el formato existente.

---

*Desarrollado con fines educativos y de seguridad defensiva.*  
*Si encuentras secretos expuestos, actúa de forma responsable.*
