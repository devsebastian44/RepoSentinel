"""
core/scanner.py — Motor de análisis de repositorios.

Responsabilidades:
  1. Recibir metadata de repositorios de la API de GitHub.
  2. Listar los archivos del repositorio (árbol).
  3. Filtrar archivos candidatos (tamaño, extensión, nombre sensible).
  4. Analizar contenido de archivos con las reglas de patterns.py.
  5. Detectar archivos sensibles con las reglas de sensitive_files.py.
  6. Cargar y aplicar reglas personalizadas desde custom_rules.yaml.
  7. Devolver un ScanResult completo por repositorio.
  8. Usar concurrencia (ThreadPoolExecutor) para escanear repos en paralelo.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import yaml

import config
from core.github_api import GitHubClient
from core.logger import get_logger
from rules.patterns import RULES, Rule
from rules.sensitive_files import match_sensitive_file

log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Modelos de datos
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class Finding:
    """Representa una vulnerabilidad detectada en un archivo."""

    rule_id: str
    rule_name: str
    severity: str
    category: str
    description: str
    file_path: str
    line_number: int
    line_content: str  # fragmento censurado de la línea


@dataclass
class SensitiveFileHit:
    """Representa un archivo sensible detectado por su nombre."""

    rule_id: str
    rule_name: str
    severity: str
    description: str
    file_path: str


@dataclass
class ScanResult:
    """Resultado completo del análisis de un repositorio."""

    repo_name: str
    repo_full_name: str
    repo_url: str
    repo_stars: int
    repo_language: str | None
    scan_timestamp: str
    scan_duration_s: float
    files_analyzed: int
    findings: list[Finding] = field(default_factory=list)
    sensitive_files: list[SensitiveFileHit] = field(default_factory=list)
    error: str | None = None

    # ── Agregados calculados ──────────────────────────────────────────────────

    @property
    def total_issues(self) -> int:
        return len(self.findings) + len(self.sensitive_files)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for sf in self.sensitive_files:
            counts[sf.severity] = counts.get(sf.severity, 0) + 1
        return counts

    @property
    def security_score(self) -> int:
        """
        Puntuación de seguridad de 0 a 100.
        Comienza en 100 y descuenta puntos según la severidad de los hallazgos.
        """
        penalty = sum(
            config.SEVERITY_WEIGHTS.get(sev, 0) * count
            for sev, count in self.severity_counts.items()
        )
        return max(0, 100 - penalty)

    @property
    def security_grade(self) -> str:
        """Nota de A a F basada en el security_score."""
        score = self.security_score
        for grade, threshold in sorted(
            config.SCORE_THRESHOLDS.items(), key=lambda x: -x[1]
        ):
            if score >= threshold:
                return grade
        return "F"


# ══════════════════════════════════════════════════════════════════════════════
# Cargador de reglas personalizadas
# ══════════════════════════════════════════════════════════════════════════════


def _load_custom_rules(
    path: Path = config.RULES_DIR / "custom_rules.yaml",
) -> list[Rule]:
    """
    Carga reglas adicionales desde un archivo YAML.

    Args:
        path: Ruta al archivo YAML de reglas personalizadas.

    Returns:
        Lista de reglas compatibles con el formato de RULES.
    """
    if not path.exists():
        return []

    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        custom = []
        for entry in data.get("rules", []):
            compiled = re.compile(entry["pattern"], re.IGNORECASE)
            custom.append(
                Rule(
                    id=entry["id"],
                    name=entry["name"],
                    description=entry.get("description", ""),
                    severity=entry.get("severity", "medium"),
                    pattern=compiled,
                    category=entry.get("category", "custom"),
                )
            )
        log.info("Cargadas %d reglas personalizadas desde '%s'.", len(custom), path)
        return custom
    except Exception as exc:
        log.warning("No se pudieron cargar reglas personalizadas: %s", exc)
        return []


# ══════════════════════════════════════════════════════════════════════════════
# Analizador de contenido
# ══════════════════════════════════════════════════════════════════════════════


class ContentAnalyzer:
    """Aplica reglas de patrones sobre el contenido de un archivo de texto."""

    def __init__(self, extra_rules: list[Rule] | None = None) -> None:
        self._rules = RULES + (extra_rules or [])

    def analyze(self, content: str, file_path: str) -> list[Finding]:
        """
        Analiza el contenido de un archivo y devuelve todos los hallazgos.

        Args:
            content:   Texto completo del archivo.
            file_path: Ruta del archivo (para el reporte).

        Returns:
            Lista de Finding con las vulnerabilidades detectadas.
        """
        findings: list[Finding] = []
        lines = content.splitlines()

        for rule in self._rules:
            for line_no, line in enumerate(lines, start=1):
                try:
                    match = rule["pattern"].search(line)
                    if match:
                        findings.append(
                            Finding(
                                rule_id=rule["id"],
                                rule_name=rule["name"],
                                severity=rule["severity"],
                                category=rule["category"],
                                description=rule["description"],
                                file_path=file_path,
                                line_number=line_no,
                                line_content=self._redact(line.strip()[:200]),
                            )
                        )
                        break  # Una ocurrencia por regla/archivo es suficiente
                except re.error:
                    pass  # Regex inválida en regla personalizada

        return findings

    @staticmethod
    def _redact(text: str) -> str:
        """
        Censurado parcial: muestra los primeros 4 caracteres del valor
        sensible y reemplaza el resto con asteriscos.
        Esto preserva contexto sin exponer el secreto completo.
        """
        # Sustituye secuencias que parecen secretos (16+ chars alfanuméricos)
        redacted = re.sub(
            r"([A-Za-z0-9+/=_\-]{4})([A-Za-z0-9+/=_\-]{12,})",
            lambda m: m.group(1) + "*" * min(len(m.group(2)), 8),
            text,
        )
        return redacted


# ══════════════════════════════════════════════════════════════════════════════
# Scanner principal
# ══════════════════════════════════════════════════════════════════════════════


class RepositoryScanner:
    """
    Orquesta el escaneo de repositorios de GitHub.

    Flujo por repositorio:
      1. Obtener árbol de archivos.
      2. Filtrar por extensión e ignorar archivos grandes.
      3. Detectar archivos sensibles por nombre.
      4. Descargar y analizar contenido de archivos elegibles.
      5. Devolver ScanResult.
    """

    def __init__(self, client: GitHubClient | None = None) -> None:
        self._client = client or GitHubClient()
        self._analyzer = ContentAnalyzer(extra_rules=_load_custom_rules())

    # ── Escaneo de un único repositorio ──────────────────────────────────────

    def scan_repo(self, repo: dict) -> ScanResult:
        """
        Escanea un repositorio completo.

        Args:
            repo: Dict de metadata del repositorio devuelto por la API de GitHub.

        Returns:
            ScanResult con todos los hallazgos.
        """
        full_name = repo.get("full_name", "unknown/unknown")
        owner, name = full_name.split("/", 1)
        start_ts = time.time()

        log.info("⏳ Escaneando '%s'…", full_name)

        result = ScanResult(
            repo_name=name,
            repo_full_name=full_name,
            repo_url=repo.get("html_url", ""),
            repo_stars=repo.get("stargazers_count", 0),
            repo_language=repo.get("language"),
            scan_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            scan_duration_s=0.0,
            files_analyzed=0,
        )

        try:
            default_branch = repo.get("default_branch", "HEAD")
            tree = self._client.get_file_tree(owner, name, branch=default_branch)

            # Filtrar: solo blobs (archivos), no árboles ni submodules
            file_nodes = [n for n in tree if n.get("type") == "blob"]

            # Aplicar límite de archivos
            if len(file_nodes) > config.MAX_FILES_PER_REPO:
                log.debug(
                    "'%s' tiene %d archivos; limitando a %d.",
                    full_name,
                    len(file_nodes),
                    config.MAX_FILES_PER_REPO,
                )
                file_nodes = file_nodes[: config.MAX_FILES_PER_REPO]

            # ── Paso 1: detección de archivos sensibles por nombre ───────────
            for node in file_nodes:
                path = node.get("path", "")
                hits = match_sensitive_file(path)
                for rule in hits:
                    result.sensitive_files.append(
                        SensitiveFileHit(
                            rule_id=rule["id"],
                            rule_name=rule["name"],
                            severity=rule["severity"],
                            description=rule["description"],
                            file_path=path,
                        )
                    )

            # ── Paso 2: análisis de contenido ─────────────────────────────────
            eligible = self._filter_eligible(file_nodes)
            log.debug(
                "'%s': %d archivos elegibles para análisis de contenido.",
                full_name,
                len(eligible),
            )

            for node in eligible:
                path = node.get("path", "")
                size = node.get("size", 0)

                if size > config.MAX_FILE_SIZE:
                    log.debug("Omitiendo '%s' (tamaño=%d bytes).", path, size)
                    continue

                content = self._client.get_file_content(
                    owner, name, path, branch=default_branch
                )
                if content is None:
                    continue

                findings = self._analyzer.analyze(content, path)
                result.findings.extend(findings)
                result.files_analyzed += 1

        except Exception as exc:
            log.error("Error escaneando '%s': %s", full_name, exc)
            result.error = str(exc)

        result.scan_duration_s = round(time.time() - start_ts, 2)

        counts = result.severity_counts
        log.info(
            "✅ '%s' — Score: %d (%s) | Issues: %d "
            "(critical=%d, high=%d, medium=%d, low=%d) | %.1fs",
            full_name,
            result.security_score,
            result.security_grade,
            result.total_issues,
            counts["critical"],
            counts["high"],
            counts["medium"],
            counts["low"],
            result.scan_duration_s,
        )
        return result

    # ── Escaneo en paralelo ───────────────────────────────────────────────────

    def scan_repos(self, repos: list[dict]) -> list[ScanResult]:
        """
        Escanea múltiples repositorios usando un pool de threads.

        Args:
            repos: Lista de dicts de metadata de repositorios.

        Returns:
            Lista de ScanResult en el mismo orden que la entrada.
        """
        if not repos:
            log.warning("No hay repositorios para escanear.")
            return []

        results: list[ScanResult] = []
        log.info(
            "Iniciando escaneo de %d repositorios con %d workers…",
            len(repos),
            config.MAX_WORKERS,
        )

        with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as pool:
            future_to_repo = {pool.submit(self.scan_repo, repo): repo for repo in repos}
            for future in as_completed(future_to_repo):
                try:
                    results.append(future.result())
                except Exception as exc:
                    repo = future_to_repo[future]
                    log.error(
                        "Excepción no capturada al escanear '%s': %s",
                        repo.get("full_name"),
                        exc,
                    )

        # Ordenar por security_score ascendente (los más vulnerables primero)
        results.sort(key=lambda r: r.security_score)
        return results

    # ── Filtrado de archivos elegibles ────────────────────────────────────────

    @staticmethod
    def _filter_eligible(nodes: list[dict]) -> list[dict]:
        """
        Devuelve los nodos cuyo tipo de archivo es candidato a análisis de contenido.
        Excluye binarios, imágenes, multimedia y archivos grandes conocidos.
        """
        eligible = []
        for node in nodes:
            path = node.get("path", "")
            ext = Path(path).suffix.lower()
            if ext in config.IGNORED_EXTENSIONS:
                continue
            # Excluir directorios comunes de dependencias
            if any(
                part in path.split("/")
                for part in ("node_modules", "vendor", ".git", "__pycache__")
            ):
                continue
            eligible.append(node)
        return eligible
