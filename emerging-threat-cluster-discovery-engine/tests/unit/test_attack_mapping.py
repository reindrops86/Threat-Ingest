from __future__ import annotations

from threat_ingestion.attack_mapping import techniques_for_family


def test_known_family_returns_techniques() -> None:
    techniques = techniques_for_family("Emotet")
    assert techniques
    assert all(t.technique_id.startswith("T") for t in techniques)


def test_lookup_is_case_and_punctuation_insensitive() -> None:
    assert techniques_for_family("Cobalt Strike") == techniques_for_family("cobaltstrike")
    assert techniques_for_family("COBALT-STRIKE") == techniques_for_family("cobaltstrike")


def test_unknown_family_returns_empty_list() -> None:
    assert techniques_for_family("totally-unknown-family-xyz") == []
