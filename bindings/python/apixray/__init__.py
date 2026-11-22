"""Python-биндинг к apixray через ctypes.

Перед использованием соберите библиотеку:

    cargo build --release -p apixray-ffi

Путь можно задать переменной окружения APIXRAY_LIB.
"""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
from typing import Any

__version__ = "0.1.0"


def _candidate_paths() -> list[Path]:
    env = os.environ.get("APIXRAY_LIB")
    paths: list[Path] = []
    if env:
        paths.append(Path(env))
    here = Path(__file__).resolve()
    for parent in here.parents:
        for profile in ("release", "debug"):
            paths.append(parent / "target" / profile / "libapixray.so")
            paths.append(parent / "target" / profile / "apixray.dll")
            paths.append(parent / "target" / profile / "libapixray.dylib")
    return paths


def _load_library() -> ctypes.CDLL:
    for path in _candidate_paths():
        if path.is_file():
            lib = ctypes.CDLL(str(path))
            lib.apixray_version.restype = ctypes.c_char_p
            lib.apixray_analyze.argtypes = [ctypes.c_char_p]
            lib.apixray_analyze.restype = ctypes.c_void_p
            lib.apixray_scan.argtypes = [ctypes.c_char_p]
            lib.apixray_scan.restype = ctypes.c_void_p
            lib.apixray_generate_fake.argtypes = [ctypes.c_char_p]
            lib.apixray_generate_fake.restype = ctypes.c_void_p
            lib.apixray_free.argtypes = [ctypes.c_void_p]
            lib.apixray_free.restype = None
            return lib
    raise RuntimeError(
        "Не найдена libapixray. Выполните: cargo build --release -p apixray-ffi "
        "или установите APIXRAY_LIB=/путь/к/libapixray.so"
    )


class ApiXray:
    def __init__(self) -> None:
        self._lib = _load_library()

    def version(self) -> str:
        return self._lib.apixray_version().decode()

    def _call_json(self, func: Any, value: str) -> Any:
        ptr = func(value.encode("utf-8"))
        if not ptr:
            raise RuntimeError("apixray вернул null")
        try:
            raw = ctypes.string_at(ptr).decode("utf-8")
        finally:
            self._lib.apixray_free(ptr)
        return json.loads(raw)

    def analyze(self, token: str) -> dict[str, Any]:
        return self._call_json(self._lib.apixray_analyze, token)

    def scan(self, text: str) -> list[dict[str, Any]]:
        return self._call_json(self._lib.apixray_scan, text)

    def generate_fake(self, provider: str) -> str:
        ptr = self._lib.apixray_generate_fake(provider.encode("utf-8"))
        if not ptr:
            raise RuntimeError("apixray вернул null")
        try:
            return ctypes.string_at(ptr).decode("utf-8")
        finally:
            self._lib.apixray_free(ptr)


__all__ = ["ApiXray", "__version__"]
