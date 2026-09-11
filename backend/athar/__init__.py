"""ATHAR — multi-cloud access governance.

Package layout mirrors the pipeline stages in docs/SPEC.md §2.1. Pure functions
(rules, scoring, Merkle, narrative) never touch the DB, the clock or the network.
"""

__version__ = "0.1.0"
