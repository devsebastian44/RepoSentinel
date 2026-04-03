#!/usr/bin/env python3
"""
main.py — Punto de entrada del CLI de GitHub Security Scanner.

Uso básico:
    python main.py keyword "django secret key" --max-repos 5
    python main.py user torvalds --max-repos 3
    python main.py trending --language python --max-repos 10

Para más opciones:
    python main.py --help
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from pathlib import Path

# Asegurar que el directorio raíz esté en el path de imports
sys.path.insert(0, str(Path(__file__).parent))

import config
from core.github_api import GitHubClient, RateLimitError
from core.logger import get_logger
from core.scanner import RepositoryScanner
from reports.reporter import ReportManager

log = get_logger("main")


# ══════════════════════════════════════════════════════════════════════════════
# Banner
# ══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██╗  ██╗    ███████╗███████╗ ██████╗              ║
║  ██╔════╝ ██║  ██║    ██╔════╝██╔════╝██╔════╝              ║
║  ██║  ███╗███████║    ███████╗█████╗  ██║                   ║
║  ██║   ██║██╔══██║    ╚════██║██╔══╝  ██║                   ║
║  ╚██████╔╝██║  ██║    ███████║███████╗╚██████╗              ║
║   ╚═════╝ ╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝              ║
║                                                              ║
║         GitHub Security Scanner  v1.0.0                     ║
║         Pentesting automatizado de repositorios             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="github-security-scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""
        GitHub Security Scanner — Herramienta de análisis de seguridad para
        repositorios públicos de GitHub.

        Detecta secretos expuestos, credenciales hardcodeadas y archivos
        sensibles mediante expresiones regulares y reglas personalizables.
        """),
        epilog=textwrap.dedent("""
        Ejemplos:
          # Escanear por URL de repositorio
          python main.py url https://github.com/octocat/Spoon-Knife

          # Escanear por palabra clave
          python main.py keyword "aws secret key" --max-repos 5

          # Escanear repositorios de un usuario
          python main.py user octocat --max-repos 10

          # Escanear repositorios trending de Python
          python main.py trending --language python --max-repos 8

          # Generar solo reporte JSON
          python main.py keyword "django" --format json

          # Verificar estado del rate-limit
          python main.py rate-limit
        """),
    )

    # ── Subcomandos ────────────────────────────────────────────────────────────
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMANDO")

    # keyword
    kw = sub.add_parser("keyword", help="Buscar repositorios por palabra clave.")
    kw.add_argument("query", help="Término de búsqueda (p.ej. 'aws secret key').")
    kw.add_argument(
        "--language", "-l", help="Filtrar por lenguaje (python, javascript, …)."
    )

    # user
    us = sub.add_parser(
        "user", help="Escanear repositorios de un usuario u organización."
    )
    us.add_argument("username", help="Nombre de usuario o organización en GitHub.")

    # trending
    tr = sub.add_parser(
        "trending", help="Escanear repositorios trending de la última semana."
    )
    tr.add_argument("--language", "-l", help="Filtrar por lenguaje.")

    # url
    ur = sub.add_parser("url", help="Escanear un repositorio específico por su URL.")
    ur.add_argument(
        "url", help="URL del repositorio de GitHub (ej. https://github.com/user/repo)."
    )

    # rate-limit
    sub.add_parser(
        "rate-limit", help="Mostrar el estado del rate-limit de la API de GitHub."
    )

    # ── Opciones globales ──────────────────────────────────────────────────────
    for p in (kw, us, tr, ur):
        p.add_argument(
            "--max-repos",
            "-n",
            type=int,
            default=config.MAX_REPOS,
            metavar="N",
            help=f"Número máximo de repositorios a escanear (default: {config.MAX_REPOS}).",
        )
        p.add_argument(
            "--workers",
            "-w",
            type=int,
            default=config.MAX_WORKERS,
            metavar="N",
            help=f"Hilos paralelos para el escaneo (default: {config.MAX_WORKERS}).",
        )
        p.add_argument(
            "--format",
            "-f",
            nargs="+",
            choices=["md", "json"],
            default=["md", "json"],
            metavar="FMT",
            help="Formatos de reporte a generar: md, json (default: ambos).",
        )
        p.add_argument(
            "--output-dir",
            "-o",
            type=Path,
            default=config.REPORTS_DIR,
            metavar="DIR",
            help=f"Directorio de salida para los reportes (default: {config.REPORTS_DIR}).",
        )
        p.add_argument(
            "--token",
            "-t",
            default=None,
            metavar="TOKEN",
            help="Token de GitHub (también puede configurarse con GITHUB_TOKEN env var).",
        )
        p.add_argument(
            "--no-banner",
            action="store_true",
            help="Suprimir el banner de inicio.",
        )

    return parser


# ══════════════════════════════════════════════════════════════════════════════
# Lógica principal
# ══════════════════════════════════════════════════════════════════════════════


def run(args: argparse.Namespace) -> int:
    """
    Ejecuta el flujo principal según el subcomando elegido.

    Returns:
        Código de salida (0 = éxito, 1 = error).
    """
    # Aplicar opciones dinámicas antes de instanciar clientes
    if hasattr(args, "workers"):
        config.MAX_WORKERS = args.workers

    token = getattr(args, "token", None) or config.GITHUB_TOKEN
    client = GitHubClient(token=token)
    scanner = RepositoryScanner(client=client)
    manager = ReportManager(output_dir=getattr(args, "output_dir", config.REPORTS_DIR))

    # ── rate-limit ─────────────────────────────────────────────────────────────
    if args.command == "rate-limit":
        status = client.get_rate_limit_status()
        print("\n📊 Estado del Rate-Limit de GitHub API:")
        print(
            f"   Core:   {status['core_remaining']}/{status['core_limit']} requests restantes"
        )
        print(
            f"   Search: {status['search_remaining']}/{status['search_limit']} requests restantes"
        )
        import time

        reset = status.get("core_reset", 0)
        wait = max(int(reset) - int(time.time()), 0)
        print(f"   Reset en: {wait}s\n")
        return 0

    # ── Búsqueda de repositorios ───────────────────────────────────────────────
    try:
        if args.command == "keyword":
            repos = client.search_repos_by_keyword(
                keyword=args.query,
                language=getattr(args, "language", None),
                max_results=args.max_repos,
            )
        elif args.command == "user":
            repos = client.search_repos_by_user(
                username=args.username,
                max_results=args.max_repos,
            )
        elif args.command == "trending":
            repos = client.get_trending_repos(
                language=getattr(args, "language", None),
                max_results=args.max_repos,
            )
        elif args.command == "url":
            repos = client.get_repo_by_url(url=args.url)
        else:
            log.error("Comando desconocido: %s", args.command)
            return 1

    except RateLimitError as exc:
        log.critical("Rate-limit de GitHub agotado: %s", exc)
        return 1
    except Exception as exc:
        log.critical("Error al buscar repositorios: %s", exc)
        return 1

    if not repos:
        log.warning("No se encontraron repositorios para los criterios dados.")
        return 0

    # ── Escaneo ────────────────────────────────────────────────────────────────
    results = scanner.scan_repos(repos)

    # ── Generación de reportes ─────────────────────────────────────────────────
    formats = tuple(getattr(args, "format", ["md", "json"]))
    out_dir = getattr(args, "output_dir", config.REPORTS_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.command == "keyword":
        prefix = f"kw_{args.query[:20].replace(' ', '_')}"
    elif args.command == "user":
        prefix = f"user_{args.username}"
    elif args.command == "trending":
        prefix = "trending"
    elif args.command == "url":
        # Extraer owner_repo de la URL para el prefijo
        owner, repo_name = client._parse_github_url(args.url)
        prefix = f"url_{owner}_{repo_name}" if owner else "url_scan"
    else:
        prefix = "report"

    paths = manager.generate_all(results, prefix=prefix, formats=formats)

    # ── Resumen en consola ─────────────────────────────────────────────────────
    _print_summary(results, paths)
    return 0


def _print_summary(results: list, paths: dict) -> None:
    """Imprime un resumen compacto en la consola."""
    total_issues = sum(r.total_issues for r in results)
    total_critical = sum(r.severity_counts["critical"] for r in results)

    print("\n" + "═" * 60)
    print("  📊 RESUMEN DEL ESCANEO")
    print("═" * 60)
    print(f"  Repositorios: {len(results)}")
    print(f"  Archivos:     {sum(r.files_analyzed for r in results)}")
    print(f"  Issues:       {total_issues}  (🔴 Críticos: {total_critical})")
    print()

    for r in results:
        grade = r.security_grade
        emoji = {"A": "✅", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}.get(grade, "❓")
        sc = r.severity_counts
        print(
            f"  {emoji} [{grade}] {r.repo_full_name:<40} "
            f"Score: {r.security_score:>3}/100 | "
            f"🔴{sc['critical']} 🟠{sc['high']} 🟡{sc['medium']} 🟢{sc['low']}"
        )

    print("\n  📁 Reportes generados:")
    for fmt, path in paths.items():
        print(f"     [{fmt.upper()}] {path}")
    print("═" * 60 + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    show_banner = not getattr(args, "no_banner", False)
    if show_banner:
        print(BANNER)

    sys.exit(run(args))


if __name__ == "__main__":
    main()
