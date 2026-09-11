"""Import shim so the export tests find their fixtures whether or not tests/unit becomes a package."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def load_export_fixtures() -> ModuleType:
    name = "athar_test_export_fixtures"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).with_name("export_fixtures.py")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
