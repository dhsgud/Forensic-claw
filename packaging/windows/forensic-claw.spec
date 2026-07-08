# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent.parent

datas = collect_data_files(
    "forensic_claw",
    includes=[
        "webui/static/*",
        "knowledge/*.hx",
        "templates/**/*",
        "skills/**/*",
    ],
    excludes=[
        "**/__pycache__",
        "**/*.pyc",
        "**/*.pyo",
    ],
)
datas += [
    (str(PROJECT_ROOT / "LICENSE"), "."),
    (str(PROJECT_ROOT / "NOTICE"), "."),
]
# sqlite-vec ships its loadable extension (vec0.dll) as package data. PyInstaller
# does not collect it automatically, so the frozen build can import sqlite_vec but
# fails at sqlite_vec.load() with "module not found" and semantic search silently
# falls back to keyword-only. Bundle the extension so vector search works in the exe.
datas += collect_data_files("sqlite_vec")

hiddenimports = collect_submodules("forensic_claw")
hiddenimports += ["sqlite_vec"]

a = Analysis(
    [str(PROJECT_ROOT / "forensic_claw" / "__main__.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["nltk", "scipy"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Forensic-Claw",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Forensic-Claw",
)
