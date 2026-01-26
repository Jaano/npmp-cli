from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

DEFAULT_ENV_FILE = ".env"
DEFAULT_VERIFY_TLS = True
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_DOCKER_LABEL_PREFIX = "npmp."
DEFAULT_LOG_FILE_NAME = "npmp-cli.log"
DEFAULT_HTTP_RETRY_COUNT = 3


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
    def load_dotenv(path: str | None = None) -> None:
        """Load env file into process env.

        Best-effort: missing python-dotenv or missing file does not break the CLI.
        """
        try:
            from dotenv import load_dotenv  # type: ignore[import-not-found]

            load_dotenv(dotenv_path=path or DEFAULT_ENV_FILE)
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
    def identity() -> str | None:
        v = os.getenv("NPMP_IDENTITY")
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
    def docker_proxy_label_prefix() -> str:
        return f"{ConfigManager.docker_label_prefix()}proxy."

    @staticmethod
    def docker_dead_host_label_prefix() -> str:
        return f"{ConfigManager.docker_label_prefix()}dead."

    @staticmethod
    def docker_redirection_host_label_prefix() -> str:
        return f"{ConfigManager.docker_label_prefix()}redirect."

    @staticmethod
    def docker_stream_label_prefix() -> str:
        return f"{ConfigManager.docker_label_prefix()}stream."

    @staticmethod
    def http_retry_count() -> int:
        """How many times to retry an HTTP request on disconnect/transport errors."""
        raw = os.getenv("NPMP_HTTP_RETRY_COUNT")
        if raw is None or not str(raw).strip():
            return DEFAULT_HTTP_RETRY_COUNT
        try:
            v = int(str(raw).strip())
        except Exception as e:
            raise ValueError("NPMP_HTTP_RETRY_COUNT must be an integer") from e
        if v < 0:
            raise ValueError("NPMP_HTTP_RETRY_COUNT must be >= 0")
        return v

    @staticmethod
    def _parse_log_level(level: str) -> int:
        normalized = (level or DEFAULT_LOG_LEVEL).strip().upper()
        try:
            logging_level = getattr(logging, normalized)
            if not isinstance(logging_level, int):
                raise AttributeError
        except Exception as e:
            raise ValueError("log_level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL") from e
        return logging_level

    @staticmethod
    def _resolve_log_file_path(value: str | os.PathLike[str] | None) -> Path | None:
        if value is None:
            return None
        raw = str(value).strip()
        if not raw:
            return None

        p = Path(os.path.expanduser(raw))
        # If a directory is provided, create a file within it.
        if p.exists() and p.is_dir():
            return p / DEFAULT_LOG_FILE_NAME
        if raw.endswith(("/", os.sep)):
            return p / DEFAULT_LOG_FILE_NAME
        return p

    @staticmethod
    def configure_logging(
        console_level: str,
        *,
        log_file: str | os.PathLike[str] | None = None,
        file_level: str | None = None,
        console_stream: str = "stderr",
    ) -> None:
        """Configure logging.

        Always logs to console. If log_file is set, also logs to that file.
        The console and file handlers can have different levels.
        """

        console_logging_level = ConfigManager._parse_log_level(console_level)
        file_logging_level = (
            ConfigManager._parse_log_level(file_level) if (file_level is not None and str(file_level).strip()) else None
        )
        file_path = ConfigManager._resolve_log_file_path(log_file)

        stream_key = (console_stream or "stderr").strip().lower()
        if stream_key == "stdout":
            console_target = sys.stdout
        elif stream_key == "stderr":
            console_target = sys.stderr
        else:
            raise ValueError("log_console_stream must be one of: stdout, stderr")

        # Console is optimized for readability; file is optimized for diagnostics.
        console_formatter = logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        file_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

        root = logging.getLogger()
        for h in list(root.handlers):
            root.removeHandler(h)

        min_level = console_logging_level
        if file_logging_level is not None:
            min_level = min(min_level, file_logging_level)

        root.setLevel(min_level)

        console_handler = logging.StreamHandler(stream=console_target)
        console_handler.setLevel(console_logging_level)
        console_handler.setFormatter(console_formatter)
        root.addHandler(console_handler)

        if file_path is not None:
            try:
                file_path.parent.mkdir(parents=True, exist_ok=True)
                fh = logging.FileHandler(file_path, encoding="utf-8")
                fh.setLevel(file_logging_level if file_logging_level is not None else console_logging_level)
                fh.setFormatter(file_formatter)
                root.addHandler(fh)
            except Exception as e:
                root.warning("Failed to enable file logging to %s (%s)", file_path, str(e))

        # Keep noisy HTTP libs at WARNING or higher.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)
