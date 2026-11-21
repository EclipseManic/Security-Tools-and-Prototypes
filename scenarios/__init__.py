"""scenarios package - attack simulation scenario definitions.

Scenarios are loaded from YAML files in scenarios/data/ (7 curated domain
dirs). Format v1 (multiple-choice) and format v2 (free-text) are both
supported. Legacy Python scenario classes were removed in P2.
"""

from scenarios.loader import (
    load_all,
    ALL_CATEGORIES,
    SCENARIO_BY_ID,
    TOTAL_SCENARIOS,
)
