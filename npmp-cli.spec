# pyinstaller spec file

from __future__ import annotations

import os
from pathlib import Path

block_cipher = None
target_arch = os.environ.get("PYINSTALLER_TARGET_ARCH") or None

project_root = Path(SPECPATH)
src_path = str(project_root / "src")


a = Analysis(
    [str(project_root / "npmp-cli.py")],
    pathex=[str(project_root), src_path],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="npmp-cli",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=target_arch,
    codesign_identity=None,
    entitlements_file=None,
)
