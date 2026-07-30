from __future__ import annotations

from redcell.randomness import (
    MAX_SIGNED_64_BIT,
    controller_seed_for,
    derive_seed,
    seeds_for_attempt,
)


def test_seed_derivation_is_stable_and_domain_separated() -> None:
    assert derive_seed(42, "attempt", 7) == derive_seed(42, "attempt", 7)
    assert derive_seed(42, "attempt", 7) == 8438188232295939894
    assert controller_seed_for(42) == 845112907261466825
    assert derive_seed(42, "attempt", 7) != derive_seed(42, "attempt", 8)
    assert derive_seed(42, "generator") != derive_seed(42, "target")


def test_seed_fits_signed_64_bit_storage() -> None:
    seed = derive_seed(2**63, "large", 999)
    assert 0 <= seed <= MAX_SIGNED_64_BIT


def test_attempt_seed_tree_is_repeatable() -> None:
    first = seeds_for_attempt(42, 37)
    second = seeds_for_attempt(42, 37)

    assert first == second
    assert first.controller_seed == controller_seed_for(42)
    assert (
        len(
            {
                first.attempt_seed,
                first.generator_seed,
                first.actor_seed,
                first.target_seed,
            }
        )
        == 4
    )


def test_different_attempts_do_not_share_random_domains() -> None:
    first = seeds_for_attempt(42, 0)
    second = seeds_for_attempt(42, 1)

    assert first.attempt_seed != second.attempt_seed
    assert first.generator_seed != second.generator_seed


def test_negative_attempt_index_is_rejected() -> None:
    try:
        seeds_for_attempt(42, -1)
    except ValueError as exc:
        assert "attempt_index" in str(exc)
    else:
        raise AssertionError("negative attempt_index should fail")
