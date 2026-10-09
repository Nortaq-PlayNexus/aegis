"""Suite modules. Each exposes `check_*` functions taking a RunContext.

A function's name is the capability id minus its domain prefix:
    aegis.suites.s05_detection:defense_impairment_gap
        -> s05_detection.defense_impairment_gap
"""
from . import (s01_recon, s02_surface, s03_identity, s04_supplychain,
               s05_detection, s06_response, s07_aisec, s08_lab, s09_assure)

__all__ = ["s01_recon", "s02_surface", "s03_identity", "s04_supplychain",
           "s05_detection", "s06_response", "s07_aisec", "s08_lab", "s09_assure"]
