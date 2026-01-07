from __future__ import annotations

import os
from pathlib import Path

import pytest


def pytest_configure(config: pytest.Config) -> None:
	# Optional: load env vars for integration tests from a specified dotenv file.
	# Unit tests do not depend on these.
	env_file = os.getenv("NPMP_ENV_FILE")
	if not env_file:
		return

	try:
		from dotenv import load_dotenv

		p = Path(env_file)
		if p.exists():
			load_dotenv(dotenv_path=p)
	except Exception:
		# Keep tests runnable even if python-dotenv isn't present for some reason.
		return
