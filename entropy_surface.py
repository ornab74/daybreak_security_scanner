"""NumPy mechanics for bounded, locality-aware evidence aggregation."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable

import numpy as np

DOMAINS = ("capability", "exposure", "resilience", "trajectory")
DOMAIN_INDEX = {name: index for index, name in enumerate(DOMAINS)}
# Directed propagation: rows are sources and columns are destinations. Diagonal
# values are zero so a locality cannot amplify itself.
COUPLING = np.array([
    [0.00, 0.20, 0.08, 0.06],
    [0.20, 0.00, 0.08, 0.05],
    [0.06, 0.08, 0.00, 0.14],
    [0.05, 0.06, 0.16, 0.00],
], dtype=np.float64)


@dataclass(frozen=True)
class SurfaceState:
    domain_charge: np.ndarray
    lattice_charge: float
    repulsion_loss: float
    contradiction_charge: float


def _field(signal, name: str, default):
    if isinstance(signal, dict):
        return signal.get(name, default)
    return getattr(signal, name, default)


def _semantic_vector(text: str, dimensions: int = 64) -> np.ndarray:
    """Deterministic signed feature hashing; local and embedding-service free."""
    vector = np.zeros(dimensions, dtype=np.float64)
    for token in re.findall(r"[a-z0-9_.:/+-]+", text.lower())[:128]:
        digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        vector[value % dimensions] += 1.0 if value & 1 else -1.0
    norm = np.linalg.norm(vector)
    return vector / norm if norm else vector


def analyze_surface(signals: Iterable, domain_weights: dict[str, float]) -> SurfaceState:
    """Aggregate evidence through three bounded NumPy mechanics.

    1. Evidence charge lattice couples only different localities.
    2. Locality repulsion discounts semantically redundant evidence.
    3. Contradiction capacitors retain opposing charge as uncertainty.
    """
    records = []
    for signal in signals:
        domain = str(_field(signal, "domain", ""))
        if domain not in DOMAIN_INDEX:
            continue
        strength = np.clip(float(_field(signal, "strength", 0.0)), 0.0, 1.0)
        confidence = np.clip(float(_field(signal, "confidence", 0.0)), 0.0, 1.0)
        polarity = str(_field(signal, "polarity", "support"))
        evidence = str(_field(signal, "evidence", ""))
        records.append((DOMAIN_INDEX[domain], strength * confidence, polarity, _semantic_vector(evidence)))

    charges = np.zeros(len(DOMAINS), dtype=np.float64)
    repulsion_loss = 0.0
    contradiction = 0.0
    for domain_index in range(len(DOMAINS)):
        local = [record for record in records if record[0] == domain_index]
        local.sort(key=lambda record: record[1], reverse=True)
        accepted: dict[str, list[np.ndarray]] = {"support": [], "oppose": []}
        supporting, opposing = 0.0, 0.0
        for _, raw_charge, polarity, vector in local[:12]:
            polarity_group = "support" if polarity == "support" else "oppose"
            similarity = max((float(np.dot(vector, prior)) for prior in accepted[polarity_group]), default=0.0)
            similarity = float(np.clip(similarity, 0.0, 1.0))
            retained = raw_charge * (1.0 - 0.82 * similarity)
            repulsion_loss += raw_charge - retained
            if polarity == "support":
                supporting += retained
            else:
                opposing += retained
            if np.linalg.norm(vector):
                accepted[polarity_group].append(vector)
        # Opposing evidence is stored rather than silently averaged away. The
        # smaller side is unresolved capacitor charge; only the remainder flows.
        stored = min(supporting, opposing)
        contradiction += stored
        net = max(0.0, supporting - opposing)
        charges[domain_index] = min(1.0, net) * domain_weights[DOMAINS[domain_index]]

    normalized = charges / np.array([domain_weights[d] for d in DOMAINS], dtype=np.float64)
    propagation = normalized @ COUPLING
    # Coupling contributes only where the destination already has evidence, making
    # it a corroboration mechanic rather than charge creation.
    lattice = float(np.sum(propagation * np.minimum(normalized, 1.0)) / len(DOMAINS))
    return SurfaceState(charges, lattice, repulsion_loss, contradiction)
