from __future__ import annotations

import logging
import os

DEFAULT_ENV_FILE = ".env"
DEFAULT_VERIFY_TLS = True
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_DOCKER_LABEL_PREFIX = "npmp."


class ConfigManager:
    """Centralized configuration.

    - Loads `.env` (or `NPMP_ENV_FILE`) best-effort via python-dotenv.
    - Reads runtime config from environment variables.
    - Assigns project defaults consistently.
    """

    @staticmethod
    def _env_bool(value: str | None, *, default: bool) -> bool:
        if value is None:
            return default
        s = value.strip().lower()
        return s not in {"0", "false", "no", "off"}

    @staticmethod
    def load_dotenv_best_effort() -> None:
        """Load `.env` (or `NPMP_ENV_FILE`) into process env.

        This is intentionally best-effort: missing python-dotenv or missing file
        must not break the CLI.
        """
        try:
            from dotenv import load_dotenv  # type: ignore[import-not-found]

            env_file = os.getenv("NPMP_ENV_FILE")
            load_dotenv(dotenv_path=env_file or DEFAULT_ENV_FILE)
        except Exception:
            return

    @staticmethod
    def base_url() -> str | None:
        v = os.getenv("NPMP_BASE_URL")
        return v.strip() if v and v.strip() else None

    @staticmethod
    def token() -> str | None:
        v = os.getenv("NPMP_TOKEN")
        return v.strip() if v and v.strip() else None

    @staticmethod
    def secret() -> str | None:
        v = os.getenv("NPMP_SECRET")
        return v

    @staticmethod
    def verify_tls() -> bool:
        return ConfigManager._env_bool(os.getenv("NPMP_VERIFY_TLS"), default=DEFAULT_VERIFY_TLS)

    @staticmethod
    def log_level() -> str:
        v = os.getenv("NPMP_LOG_LEVEL")
        return (v or DEFAULT_LOG_LEVEL).strip().upper() or DEFAULT_LOG_LEVEL

    @staticmethod
    def docker_label_prefix() -> str:
        s = (os.getenv("NPMP_DOCKER_LABEL_PREFIX") or "").strip()
        if not s:
            return DEFAULT_DOCKER_LABEL_PREFIX
        if s.endswith((".", "-")):
            return s
        return s + "."

    @staticmethod
    def configure_logging(level: str) -> None:
        normalized = (level or DEFAULT_LOG_LEVEL).strip().upper()
        try:
            logging_level = getattr(logging, normalized)
            if not isinstance(logging_level, int):
                raise AttributeError
        except Exception as e:
            raise ValueError("log_level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL") from e

        logging.basicConfig(
            level=logging_level,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        logging.getLogger("httpx").setLevel(max(logging_level, logging.WARNING))
        logging.getLogger("httpcore").setLevel(max(logging_level, logging.WARNING))

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)
