"""Report kinds the analysis pipeline knows about. Each scanner module registers itself."""

import importlib

# Modules that call register() on import. An extension branch adds its module here.
SCANNER_MODULES = ("pipeline.code_scanner",)

SCANNERS = {}  # kind -> callable(root, files) -> report dict, or None when nothing applies
COMPONENT_KINDS = {}  # CBOM component type -> kind, for importing existing scanner exports
IMPORT_HOOKS = {}  # kind -> callable(component, report) -> component, run on imported components


def register(kind, scanner, component_types=(), import_hook=None):
    SCANNERS[kind] = scanner
    for component_type in component_types:
        COMPONENT_KINDS[component_type] = kind
    if import_hook:
        IMPORT_HOOKS[kind] = import_hook


def load_scanners():
    for module in SCANNER_MODULES:
        importlib.import_module(module)
    return SCANNERS
