"""
reports/reporter.py — Generación de reportes de pentest.

Formatos soportados:
  - Markdown (.md): Reporte legible con secciones, tablas y badges.
  - JSON (.json):   Datos estructurados para integración con otras herramientas.

El módulo es independiente del scanner y sólo consume ScanResult.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import config
from core.logger import get_logger
from core.scanner import ScanResult

log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Helpers de formato
# ══════════════════════════════════════════════════════════════════════════════

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}

_GRADE_BADGE = {
    "A": "![A](https://img.shields.io/badge/Security-A-brightgreen)",
    "B": "![B](https://img.shields.io/badge/Security-B-green)",
    "C": "![C](https://img.shields.io/badge/Security-C-yellow)",
    "D": "![D](https://img.shields.io/badge/Security-D-orange)",
    "F": "![F](https://img.shields.io/badge/Security-F-red)",
}


def _severity_badge(sev: str) -> str:
    colors = {
        "critical": "critical",
        "high": "important",
        "medium": "yellow",
        "low": "informational",
    }
    return f"![{sev.upper()}](https://img.shields.io/badge/Severity-{sev.upper()}-{colors.get(sev, 'lightgrey')})"


def _table_row(*cols: object) -> str:
    return "| " + " | ".join(str(c) for c in cols) + " |"


def _table_header(*cols: str) -> str:
    header = _table_row(*cols)
    sep = "| " + " | ".join("---" for _ in cols) + " |"
    return f"{header}\n{sep}"


# ══════════════════════════════════════════════════════════════════════════════
# Reporte Markdown
# ══════════════════════════════════════════════════════════════════════════════


class MarkdownReporter:
    """Genera reportes de pentest en formato Markdown profesional."""

    def generate(
        self,
        results: list[ScanResult],
        output_path: Path | None = None,
    ) -> str:
        """
        Genera el contenido Markdown del reporte.

        Args:
            results:     Lista de ScanResult a incluir.
            output_path: Si se indica, guarda el reporte en disco.

        Returns:
            Contenido Markdown como str.
        """
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        sections = [
            self._header(now, len(results)),
            self._executive_summary(results),
            self._findings_overview(results),
        ]

        for result in results:
            sections.append(self._repo_section(result))

        sections.append(self._recommendations())
        sections.append(self._footer(now))

        md = "\n\n".join(sections)

        if output_path:
            output_path.write_text(md, encoding="utf-8")
            log.info("Reporte Markdown guardado en '%s'.", output_path)

        return md

    # ── Secciones ─────────────────────────────────────────────────────────────

    @staticmethod
    def _header(timestamp: str, repo_count: int) -> str:
        return (
            "# 🔐 GitHub Security Scanner — Reporte de Pentest\n\n"
            f"> **Generado:** {timestamp}  \n"
            f"> **Repositorios analizados:** {repo_count}  \n"
            "> **Herramienta:** GitHub Security Scanner v1.0  \n"
            "\n---"
        )

    @staticmethod
    def _executive_summary(results: list[ScanResult]) -> str:
        total_issues = sum(r.total_issues for r in results)
        total_critical = sum(r.severity_counts["critical"] for r in results)
        total_high = sum(r.severity_counts["high"] for r in results)
        total_medium = sum(r.severity_counts["medium"] for r in results)
        total_low = sum(r.severity_counts["low"] for r in results)
        avg_score = sum(r.security_score for r in results) // max(len(results), 1)
        total_files = sum(r.files_analyzed for r in results)

        return (
            "## 📊 Resumen Ejecutivo\n\n"
            f"| Métrica | Valor |\n|---|---|\n"
            f"| Repositorios analizados | **{len(results)}** |\n"
            f"| Archivos analizados | **{total_files}** |\n"
            f"| Total de issues | **{total_issues}** |\n"
            f"| 🔴 Críticos | **{total_critical}** |\n"
            f"| 🟠 Altos | **{total_high}** |\n"
            f"| 🟡 Medios | **{total_medium}** |\n"
            f"| 🟢 Bajos | **{total_low}** |\n"
            f"| Score promedio | **{avg_score}/100** |\n"
        )

    @staticmethod
    def _findings_overview(results: list[ScanResult]) -> str:
        rows = []
        for r in results:
            grade = r.security_grade
            badge = _GRADE_BADGE.get(grade, grade)
            sc = r.severity_counts
            rows.append(
                _table_row(
                    f"[{r.repo_full_name}]({r.repo_url})",
                    badge,
                    f"{r.security_score}/100",
                    r.files_analyzed,
                    r.total_issues,
                    f"🔴{sc['critical']} 🟠{sc['high']} 🟡{sc['medium']} 🟢{sc['low']}",
                )
            )

        header = _table_header(
            "Repositorio", "Nota", "Score", "Archivos", "Issues", "Desglose"
        )
        return "## 📋 Resumen por Repositorio\n\n" + header + "\n" + "\n".join(rows)

    def _repo_section(self, result: ScanResult) -> str:
        sc = result.severity_counts
        grade = result.security_grade
        parts = [
            f"## 📁 `{result.repo_full_name}`\n",
            f"- **URL:** {result.repo_url}",
            f"- **Lenguaje:** {result.repo_language or 'N/A'}",
            f"- **Estrellas:** ⭐ {result.repo_stars}",
            f"- **Score:** {result.security_score}/100 — Nota: **{grade}**",
            f"- **Issues:** {result.total_issues} "
            f"(🔴{sc['critical']} 🟠{sc['high']} 🟡{sc['medium']} 🟢{sc['low']})",
            f"- **Archivos analizados:** {result.files_analyzed}",
            f"- **Duración del scan:** {result.scan_duration_s}s",
        ]

        if result.error:
            parts.append(f"\n> ⚠️ **Error durante el escaneo:** `{result.error}`")

        # Archivos sensibles
        if result.sensitive_files:
            parts.append("\n### 🗂️ Archivos Sensibles Detectados\n")
            parts.append(_table_header("Archivo", "Regla", "Severidad", "Descripción"))
            for sf in result.sensitive_files:
                emoji = _SEVERITY_EMOJI.get(sf.severity, "⚪")
                parts.append(
                    _table_row(
                        f"`{sf.file_path}`",
                        sf.rule_name,
                        f"{emoji} {sf.severity.upper()}",
                        sf.description,
                    )
                )

        # Findings de contenido
        if result.findings:
            parts.append("\n### 🔍 Vulnerabilidades en Contenido\n")
            parts.append(
                _table_header("Archivo", "Línea", "Regla", "Severidad", "Extracto")
            )
            for f in sorted(result.findings, key=lambda x: x.severity):
                emoji = _SEVERITY_EMOJI.get(f.severity, "⚪")
                parts.append(
                    _table_row(
                        f"`{f.file_path}`",
                        str(f.line_number),
                        f.rule_name,
                        f"{emoji} {f.severity.upper()}",
                        f"`{f.line_content}`",
                    )
                )

        if result.total_issues == 0:
            parts.append(
                "\n> ✅ **No se detectaron vulnerabilidades en este repositorio.**"
            )

        return "\n".join(parts)

    @staticmethod
    def _recommendations() -> str:
        return (
            "## 🛡️ Recomendaciones Generales\n\n"
            "1. **Nunca committees secretos.** Usa variables de entorno o gestores de secretos "
            "(AWS Secrets Manager, HashiCorp Vault, GitHub Secrets).\n"
            "2. **Añade `.env` a `.gitignore`** antes de cualquier commit inicial.\n"
            "3. **Usa herramientas de pre-commit** como `git-secrets`, `detect-secrets` o "
            "`truffleHog` para prevenir fugas en el lado del desarrollador.\n"
            "4. **Activa GitHub Secret Scanning** en todos los repositorios de tu organización.\n"
            "5. **Rota inmediatamente** cualquier secreto expuesto — asumir que fue comprometido.\n"
            "6. **Audita el historial de git** (`git log`) ya que los secretos borrados pueden "
            "seguir presentes en commits anteriores.\n"
            "7. **Usa archivos `.env.example`** con valores ficticios como documentación.\n"
            "8. **Implementa SAST** en tu pipeline de CI/CD (Semgrep, CodeQL, Snyk).\n"
        )

    @staticmethod
    def _footer(timestamp: str) -> str:
        return (
            "---\n\n"
            "*Reporte generado automáticamente por GitHub Security Scanner.*  \n"
            f"*Fecha: {timestamp}*  \n"
            "*Este reporte es confidencial. No distribuir sin autorización.*"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Reporte JSON
# ══════════════════════════════════════════════════════════════════════════════


class JSONReporter:
    """Genera reportes estructurados en formato JSON."""

    def generate(
        self,
        results: list[ScanResult],
        output_path: Path | None = None,
    ) -> dict:
        """
        Genera el dict JSON del reporte.

        Args:
            results:     Lista de ScanResult.
            output_path: Si se indica, serializa a disco.

        Returns:
            Dict con el reporte completo.
        """
        now = datetime.now(UTC).isoformat()

        report = {
            "meta": {
                "tool": "github-security-scanner",
                "version": "1.0.0",
                "generated_at": now,
                "repos_scanned": len(results),
            },
            "summary": self._build_summary(results),
            "repositories": [self._result_to_dict(r) for r in results],
        }

        if output_path:
            output_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            log.info("Reporte JSON guardado en '%s'.", output_path)

        return report

    @staticmethod
    def _build_summary(results: list[ScanResult]) -> dict:
        total_sc = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in results:
            for sev, count in r.severity_counts.items():
                total_sc[sev] += count

        return {
            "total_issues": sum(r.total_issues for r in results),
            "files_analyzed": sum(r.files_analyzed for r in results),
            "severity_counts": total_sc,
            "average_score": sum(r.security_score for r in results)
            // max(len(results), 1),
            "repos_with_critical": sum(
                1 for r in results if r.severity_counts["critical"] > 0
            ),
        }

    @staticmethod
    def _result_to_dict(result: ScanResult) -> dict:
        return {
            "repo": {
                "name": result.repo_name,
                "full_name": result.repo_full_name,
                "url": result.repo_url,
                "stars": result.repo_stars,
                "language": result.repo_language,
            },
            "scan": {
                "timestamp": result.scan_timestamp,
                "duration_s": result.scan_duration_s,
                "files_analyzed": result.files_analyzed,
                "error": result.error,
            },
            "score": {
                "value": result.security_score,
                "grade": result.security_grade,
            },
            "severity_counts": result.severity_counts,
            "total_issues": result.total_issues,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "category": f.category,
                    "description": f.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "line_content": f.line_content,
                }
                for f in result.findings
            ],
            "sensitive_files": [
                {
                    "rule_id": sf.rule_id,
                    "rule_name": sf.rule_name,
                    "severity": sf.severity,
                    "description": sf.description,
                    "file": sf.file_path,
                }
                for sf in result.sensitive_files
            ],
        }


# ══════════════════════════════════════════════════════════════════════════════
# Fachada pública
# ══════════════════════════════════════════════════════════════════════════════


class ReportManager:
    """
    Gestiona la generación y persistencia de todos los formatos de reporte.
    """

    def __init__(self, output_dir: Path = config.REPORTS_DIR) -> None:
        self._output_dir = output_dir
        self._md_reporter = MarkdownReporter()
        self._json_reporter = JSONReporter()

    def generate_all(
        self,
        results: list[ScanResult],
        prefix: str = "report",
        formats: tuple[str, ...] = ("md", "json"),
    ) -> dict[str, Path]:
        """
        Genera reportes en todos los formatos solicitados.

        Args:
            results: Lista de ScanResult a reportar.
            prefix:  Prefijo para el nombre de los archivos de salida.
            formats: Tupla de formatos a generar ("md", "json").

        Returns:
            Dict con {formato: ruta_del_archivo}.
        """
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        paths: dict[str, Path] = {}

        if "md" in formats:
            md_path = self._output_dir / f"{prefix}_{ts}.md"
            self._md_reporter.generate(results, output_path=md_path)
            paths["md"] = md_path

        if "json" in formats:
            json_path = self._output_dir / f"{prefix}_{ts}.json"
            self._json_reporter.generate(results, output_path=json_path)
            paths["json"] = json_path

        log.info("Reportes generados: %s", {k: str(v) for k, v in paths.items()})
        return paths
