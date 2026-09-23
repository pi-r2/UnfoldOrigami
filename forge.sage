#!/usr/bin/env sage
"""Public sequential-inversion attack on Origami-128.

The mathematical attack is kept here; byte encodings, hashing, compact-key
expansion, and the coordinate permutation live in ``technical.py``.
No secret-key material is read or used.
"""

import random

from technical import (
    N, ZONES, Origami128PublicMap, pack_gf,
    solve_linear_system, target_for_message,
)

def solve(rows, right_hand_side):
    """Solve one zone system in the submitted nibble representation."""
    return solve_linear_system(rows, right_hand_side)

def invert(public_map, target, random_seed=1, max_trials=100):
    """Invert each triangular zone after choosing its vinegar variables."""
    for trial in range(max_trials):
        rng = random.Random(int(random_seed + trial))
        secret_input = [0] * N

        for zone, (n0, m0, vinegar_count, oil_count, equation_count) in enumerate(ZONES):
            secret_input[n0:n0 + vinegar_count] = (
                rng.randrange(16) for _ in range(vinegar_count)
            )
            oil_matrix = public_map.oil_matrix(zone, secret_input)
            oils = solve(oil_matrix, target[m0:m0 + equation_count])
            if oils is None:
                break
            secret_input[n0 + vinegar_count:n0 + vinegar_count + oil_count] = oils
        else:
            public_input = public_map.to_public_order(secret_input)
            if public_map.evaluate(public_input) != target:
                raise AssertionError("internal inversion check failed")
            return public_input, trial + 1

    raise RuntimeError("no full-rank sequential solve found")


def forge(pk, msg, slt="00000000000000000000000000000000"):
    """ Forge a signature """
    public_key = bytes.fromhex(pk)
    message = bytes.fromhex(msg)
    salt = bytes.fromhex(slt)

    public_map = Origami128PublicMap(public_key)
    target = target_for_message(message, salt)
    forged_vector, trials = invert(public_map, target)
    forged_signature = pack_gf(forged_vector) + salt

    return forged_signature
