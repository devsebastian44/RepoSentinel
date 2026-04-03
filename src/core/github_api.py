"""
core/github_api.py — Cliente para la API REST de GitHub.

Funcionalidades:
  - Autenticación por token.
  - Búsqueda de repositorios por keyword o usuario.
  - Listado de archivos de un repositorio (árbol recursivo).
  - Descarga de contenido raw de archivos.
  - Manejo automático de rate-limits con back-off exponencial.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Generator

import requests

import config
from core.logger import get_logger

log = get_logger(__name__)


class GitHubAPIError(Exception):
    """Excepción base para errores de la API de GitHub."""


class RateLimitError(GitHubAPIError):
    """Se lanza cuando se agota el rate-limit y no se puede continuar."""


class GitHubClient:
    """Cliente HTTP para la API REST de GitHub v3."""

    def __init__(self, token: str = config.GITHUB_TOKEN) -> None:
        if not token:
            log.warning(
                "No se proporcionó GITHUB_TOKEN. Las peticiones sin autenticación "
                "tienen un límite de 60 req/hora."
            )
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            }
        )

    # ── Petición base ─────────────────────────────────────────────────────────

    def _get(
        self,
        url: str,
        params: dict | None = None,
        retries: int = 3,
    ) -> dict | list:
        """
        Realiza una petición GET con manejo de rate-limit y reintentos.

        Args:
            url:     URL completa o path relativo (se prefija la base automáticamente).
            params:  Query params opcionales.
            retries: Número de reintentos ante errores transitorios.

        Returns:
            JSON deserializado (dict o list).
        """
        if not url.startswith("http"):
            url = f"{config.GITHUB_API_URL}/{url.lstrip('/')}"

        for attempt in range(1, retries + 1):
            try:
                resp = self._session.get(url, params=params, timeout=15)
                self._check_rate_limit(resp)

                if resp.status_code == 404:
                    log.debug("404 Not Found: %s", url)
                    return {}

                resp.raise_for_status()
                return resp.json()

            except RateLimitError:
                raise
            except requests.RequestException as exc:
                wait = 2**attempt
                log.warning(
                    "Error en petición (intento %d/%d): %s. Reintentando en %ds…",
                    attempt,
                    retries,
                    exc,
                    wait,
                )
                time.sleep(wait)

        raise GitHubAPIError(f"Falló tras {retries} intentos: {url}")

    def _check_rate_limit(self, resp: requests.Response) -> None:
        """Pausa o lanza excepción cuando el rate-limit está bajo."""
        remaining = int(resp.headers.get("X-RateLimit-Remaining", 9999))
        reset_ts = int(resp.headers.get("X-RateLimit-Reset", 0))

        if resp.status_code == 403 and remaining == 0:
            wait = max(reset_ts - int(time.time()), 0) + 5
            log.error("Rate-limit agotado. Esperando %ds hasta el reset…", wait)
            raise RateLimitError(f"Rate-limit agotado. Reset en {wait}s.")

        if 0 < remaining <= config.RATE_LIMIT_MIN_REM:
            log.warning(
                "Rate-limit bajo (%d requests restantes). Pausando %ss…",
                remaining,
                config.RATE_LIMIT_PAUSE,
            )
            time.sleep(config.RATE_LIMIT_PAUSE)

    # ── Búsqueda de repositorios ──────────────────────────────────────────────

    def search_repos_by_keyword(
        self,
        keyword: str,
        language: str | None = None,
        max_results: int = config.MAX_REPOS,
    ) -> list[dict]:
        """
        Busca repositorios públicos por palabra clave.

        Args:
            keyword:     Término de búsqueda.
            language:    Filtrar por lenguaje de programación (opcional).
            max_results: Límite de repositorios a devolver.

        Returns:
            Lista de dicts con metadata de cada repositorio.
        """
        query = keyword
        if language:
            query += f" language:{language}"

        log.info("Buscando repositorios: query='%s'", query)
        data = self._get(
            "search/repositories",
            params={"q": query, "sort": "stars", "per_page": min(max_results, 100)},
        )
        items = data.get("items", [])[:max_results]
        log.info("Encontrados %d repositorios.", len(items))
        return items

    def search_repos_by_user(
        self,
        username: str,
        max_results: int = config.MAX_REPOS,
    ) -> list[dict]:
        """
        Lista los repositorios públicos de un usuario u organización.

        Args:
            username:    Nombre de usuario/organización de GitHub.
            max_results: Límite de repositorios.

        Returns:
            Lista de dicts con metadata de cada repositorio.
        """
        log.info("Buscando repos del usuario '%s'…", username)
        data = self._get(
            f"users/{username}/repos",
            params={"type": "public", "per_page": min(max_results, 100)},
        )
        repos = (data if isinstance(data, list) else [])[:max_results]
        log.info("Encontrados %d repositorios para '%s'.", len(repos), username)
        return repos

    def get_trending_repos(
        self,
        language: str | None = None,
        max_results: int = config.MAX_REPOS,
    ) -> list[dict]:
        """
        Obtiene repositorios creados en la última semana ordenados por estrellas
        (aproximación a 'trending' usando la Search API).

        Args:
            language:    Filtrar por lenguaje (opcional).
            max_results: Límite de resultados.

        Returns:
            Lista de repositorios trending.
        """
        from datetime import date, timedelta

        since = (date.today() - timedelta(days=7)).isoformat()
        query = f"created:>{since}"
        if language:
            query += f" language:{language}"

        log.info("Obteniendo repositorios trending desde %s…", since)
        data = self._get(
            "search/repositories",
            params={
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": min(max_results, 100),
            },
        )
        items = data.get("items", [])[:max_results]
        log.info("Encontrados %d repositorios trending.", len(items))
        return items

    # ── Árbol de archivos ─────────────────────────────────────────────────────

    def get_file_tree(
        self,
        owner: str,
        repo: str,
        branch: str = "HEAD",
    ) -> list[dict]:
        """
        Obtiene el árbol completo de archivos de un repositorio (modo recursivo).

        Args:
            owner:  Propietario del repositorio.
            repo:   Nombre del repositorio.
            branch: Rama o SHA del commit (default: HEAD).

        Returns:
            Lista de objetos del árbol (cada uno tiene 'path', 'type', 'size', etc.).
        """
        log.debug("Obteniendo árbol de '%s/%s'…", owner, repo)
        data = self._get(
            f"repos/{owner}/{repo}/git/trees/{branch}",
            params={"recursive": "1"},
        )
        if data.get("truncated"):
            log.warning(
                "El árbol de '%s/%s' fue truncado por la API (repo muy grande).",
                owner,
                repo,
            )
        return data.get("tree", [])

    # ── Contenido de archivos ─────────────────────────────────────────────────

    def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        branch: str = "HEAD",
    ) -> str | None:
        """
        Descarga el contenido de un archivo como texto plano.

        Args:
            owner:  Propietario del repositorio.
            repo:   Nombre del repositorio.
            path:   Ruta del archivo dentro del repositorio.
            branch: Rama o SHA.

        Returns:
            Contenido del archivo como str, o None si no se puede obtener.
        """
        # Intentamos primero con la API de contenidos (devuelve base64)
        data = self._get(
            f"repos/{owner}/{repo}/contents/{path}", params={"ref": branch}
        )

        if not data:
            return None

        # Archivos > 1 MB no vienen codificados en base64; usamos raw URL
        if isinstance(data, dict) and data.get("encoding") == "base64":
            try:
                return base64.b64decode(data["content"]).decode(
                    "utf-8", errors="replace"
                )
            except Exception as exc:
                log.debug("Error decodificando base64 de '%s': %s", path, exc)
                return None

        # Fallback: raw URL
        raw_url = f"{config.GITHUB_RAW_URL}/{owner}/{repo}/{branch}/{path}"
        try:
            resp = self._session.get(raw_url, timeout=15)
            if resp.status_code == 200:
                return resp.text
        except requests.RequestException as exc:
            log.debug("Error descargando raw '%s': %s", raw_url, exc)

        return None

    # ── Info de repositorio ───────────────────────────────────────────────────

    def get_repo_info(self, owner: str, repo: str) -> dict:
        """Devuelve metadata de un repositorio específico."""
        return self._get(f"repos/{owner}/{repo}")

    def get_rate_limit_status(self) -> dict:
        """Devuelve el estado actual del rate-limit de la API."""
        data = self._get("rate_limit")
        core = data.get("resources", {}).get("core", {})
        search = data.get("resources", {}).get("search", {})
        return {
            "core_remaining": core.get("remaining"),
            "core_limit": core.get("limit"),
            "core_reset": core.get("reset"),
            "search_remaining": search.get("remaining"),
            "search_limit": search.get("limit"),
        }

    def _parse_github_url(self, url: str) -> tuple[str | None, str | None]:
        """
        Analiza una URL de GitHub para extraer el propietario y el nombre del repo.
        Soporta:
          - https://github.com/owner/repo
          - http://github.com/owner/repo.git
          - github.com/owner/repo
          - owner/repo
        """
        url = url.strip().rstrip("/")
        if url.startswith("http"):
            if "github.com/" not in url:
                return None, None
            path = url.split("github.com/")[-1]
        elif "github.com/" in url:
            path = url.split("github.com/")[-1]
        else:
            path = url

        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2:
            owner = parts[0]
            repo = parts[1].replace(".git", "")
            return owner, repo

        return None, None

    def get_repo_by_url(self, url: str) -> list[dict]:
        """
        Obtiene un repositorio a partir de su URL.
        Retorna una lista con un único dict para mantener compatibilidad con search_repos.
        """
        owner, repo_name = self._parse_github_url(url)
        if not owner or not repo_name:
            log.error("Formato de URL de GitHub no reconocido: %s", url)
            return []

        log.info("Obteniendo repositorio por URL: %s/%s", owner, repo_name)
        repo_data = self.get_repo_info(owner, repo_name)

        if not repo_data:
            log.warning("No se pudo encontrar el repositorio: %s/%s", owner, repo_name)
            return []

        return [repo_data]

    # ── Iterador paginado ─────────────────────────────────────────────────────

    def paginate(
        self,
        url: str,
        params: dict | None = None,
        max_pages: int = 10,
    ) -> Generator[dict, None, None]:
        """
        Itera sobre todas las páginas de un endpoint paginado de la API.

        Args:
            url:       URL del endpoint.
            params:    Parámetros base de la query.
            max_pages: Límite de páginas a consumir.

        Yields:
            Cada ítem de las respuestas paginadas.
        """
        params = {**(params or {}), "per_page": 100, "page": 1}
        for _ in range(max_pages):
            data = self._get(url, params=params)
            if isinstance(data, list):
                if not data:
                    break
                yield from data
            elif isinstance(data, dict):
                items = data.get("items", [])
                if not items:
                    break
                yield from items
            params["page"] += 1
