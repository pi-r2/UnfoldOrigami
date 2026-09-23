"""Wire-format and reference-expansion details for the Origami-128 attack.

This module intentionally contains the implementation-specific material.  The
attack in :mod:`origami128_public_forge` only needs the public map, its zone
matrices, and the signature/target encodings.
"""

import hashlib
import math
import struct


PARAM_ID = 0x4F4D0080
N = 200
M = 104
RPK_BYTES = 2976
NUMGF_RPK = 2 * RPK_BYTES
SIG_VECTOR_BYTES = N // 2
SALT_BYTES = 16

# (input offset, output offset, vinegar count, oil count, equation count)
ZONES = (
    (0, 0, 24, 40, 32),
    (64, 32, 24, 40, 32),
    (128, 64, 24, 40, 32),
    (192, 96, 0, 8, 8),
)

ICCS_HASH_KEY = bytes.fromhex( #from auxfunc.c: //key = SM3(UTF-8("3.14159265358979")) || SM3(UTF-8("2.71828182845904"))
    "5307f6d5eb6a3ced3d24c53cc9c82cce"
    "2f8936397023f0695c26c80c1ab182a7"
    "1db02ba92f544018115a96e719662ca3"
    "2b7c7efc0a6d2482150766ba6f655b8e"
)


def sm3(data):
    try:
        return hashlib.new("sm3", data).digest()
    except ValueError as exc:
        raise RuntimeError("This Python build does not expose SM3 through hashlib") from exc


def hmac_sm3(key, message):
    block = 64
    if len(key) > block:
        key = sm3(key)
    key += bytes(block - len(key))
    ipad = bytes(x ^ 0x36 for x in key)
    opad = bytes(x ^ 0x5C for x in key)
    return sm3(opad + sm3(ipad + message))


def pseudo_xof(message, length):
    blocks = (
        sm3(message + counter.to_bytes(4, "big"))
        for counter in range(1, (length + 31) // 32 + 1)
    )
    return b"".join(blocks)[:length]


def pseudohash_512(message):
    h1 = sm3(message + b"\x02\x00")
    k1 = hmac_sm3(ICCS_HASH_KEY, b"\x02\x00" + message)
    return h1 + sm3(k1 + h1)


def u32le(value):
    return struct.pack("<I", value)


def unpack_gf(data, count):
    """Decode GF(16) elements in the submission's low-nibble-first order."""
    elements = []
    for byte in data:
        elements.extend((byte & 0x0F, byte >> 4))
    return elements[:count]


def pack_gf(elements):
    """Encode GF(16) elements in the submission's low-nibble-first order."""
    return bytes(
        elements[i] | ((elements[i + 1] if i + 1 < len(elements) else 0) << 4)
        for i in range(0, len(elements), 2)
    )


def gf_mul(a, b):
    result = 0
    for _ in range(4):
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 0x10:
            a ^= 0x13  # x^4 + x + 1
    return result & 0x0F


def solve_linear_system(rows, right_hand_side):
    """Solve over GF(16) using the submitted low-nibble field representation."""
    row_count, column_count = len(rows), len(rows[0])
    augmented = [row[:] + [value] for row, value in zip(rows, right_hand_side)]
    rank = 0
    pivots = []
    for column in range(column_count):
        pivot = next((r for r in range(rank, row_count) if augmented[r][column]), None)
        if pivot is None:
            continue
        augmented[rank], augmented[pivot] = augmented[pivot], augmented[rank]
        inverse = next(x for x in range(1, 16)
                       if gf_mul(augmented[rank][column], x) == 1)
        augmented[rank] = [gf_mul(x, inverse) for x in augmented[rank]]
        for r in range(row_count):
            factor = augmented[r][column]
            if r != rank and factor:
                augmented[r] = [x ^ gf_mul(factor, y)
                                for x, y in zip(augmented[r], augmented[rank])]
        pivots.append(column)
        rank += 1
        if rank == row_count:
            break
    if rank != row_count:
        return None
    solution = [0] * column_count
    for row, pivot in enumerate(pivots):
        solution[pivot] = augmented[row][-1]
    return solution


class Origami128PublicMap:
    """Expand and evaluate the submitted compact public-key representation."""

    def __init__(self, public_key):
        if len(public_key) != 4 + 16 + RPK_BYTES:
            raise ValueError("Origami-128 public key must be 2996 bytes")
        if int.from_bytes(public_key[:4], "little") != PARAM_ID:
            raise ValueError("wrong Origami parameter identifier")
        self.pk_seed = public_key[4:20]
        self.residual = unpack_gf(public_key[20:], NUMGF_RPK)
        self.secret_to_public, self.public_to_secret = self._permutation()
        self.total, self.stride, self.offset = self._residual_schedule()
        self.coefficient_cache = {}

    def _permutation(self):
        permutation = list(range(N))
        stream = pseudo_xof(self.pk_seed + b"secret-to-public" + u32le(0), 2 * (N - 1))
        position = 0
        for i in range(N - 1, 0, -1):
            j = int.from_bytes(stream[position:position + 2], "little") % (i + 1)
            position += 2
            permutation[i], permutation[j] = permutation[j], permutation[i]
        inverse = [0] * N
        for secret_index, public_index in enumerate(permutation):
            inverse[public_index] = secret_index
        return permutation, inverse

    def _residual_schedule(self):
        total = sum(m * (n0 + v) * o for n0, _, v, o, m in ZONES)
        stride = ((PARAM_ID << 1) | 1) % total
        if not stride & 1:
            stride += 1
        stride = max(stride, 1)
        while math.gcd(stride, total) != 1:
            stride = stride + 2 if stride + 2 < total else 1
        mask = (1 << 64) - 1
        accumulator = (0x9E3779B97F4A7C15 ^ PARAM_ID) & mask
        for byte in self.pk_seed:
            term = (byte + 0x9E3779B97F4A7C15 + ((accumulator << 6) & mask)
                    + (accumulator >> 2)) & mask
            accumulator = (accumulator ^ term) & mask
        return total, stride, accumulator % total

    def _seed_coefficients(self, equation, count):
        key = (equation, count)
        if key not in self.coefficient_cache:
            data = (self.pk_seed + b"P_affine" + u32le(equation) + u32le(N)
                    + u32le(PARAM_ID) + u32le(0))
            self.coefficient_cache[key] = unpack_gf(pseudo_xof(data, 4096), count)
        return self.coefficient_cache[key]

    @staticmethod
    def _zone_base(zone):
        return sum(m * (n0 + v) * o for n0, _, v, o, m in ZONES[:zone])

    def _coefficient(self, canonical_index, seed_coefficient):
        rank = (canonical_index * self.stride + self.offset) % self.total
        return self.residual[rank] if rank < NUMGF_RPK else seed_coefficient

    def oil_matrix(self, zone, secret_input):
        n0, m0, v, o, m = ZONES[zone]
        known_count = n0 + v
        zone_base = self._zone_base(zone)
        rows = []
        for equation in range(m):
            seeded = self._seed_coefficients(m0 + equation, known_count * o)
            equation_base = zone_base + equation * known_count * o
            row = []
            for oil in range(o):
                value = 0
                for known in range(known_count):
                    local = known * o + oil
                    coefficient = self._coefficient(equation_base + local, seeded[local])
                    value ^= gf_mul(coefficient, secret_input[known])
                row.append(value)
            rows.append(row)
        return rows

    def to_public_order(self, secret_input):
        public_input = [0] * N
        for secret_index, value in enumerate(secret_input):
            public_input[self.secret_to_public[secret_index]] = int(value)
        return public_input

    def evaluate(self, public_input):
        if len(public_input) != N:
            raise ValueError("public input must contain 200 GF(16) elements")
        secret_input = [0] * N
        for public_index, value in enumerate(public_input):
            secret_input[self.public_to_secret[public_index]] = value
        result = [0] * M
        for zone, (n0, m0, v, o, m) in enumerate(ZONES):
            matrix_rows = self.oil_matrix(zone, secret_input)
            oils = secret_input[n0 + v:n0 + v + o]
            for equation in range(m):
                value = 0
                for coefficient, oil in zip(matrix_rows[equation], oils):
                    value ^= gf_mul(coefficient, oil)
                result[m0 + equation] = value
        return result


def target_for_message(message, salt):
    if len(salt) != SALT_BYTES:
        raise ValueError("Origami-128 salt must be 16 bytes")
    digest = pseudohash_512(message)
    return unpack_gf(pseudo_xof(b"target" + digest + salt, M // 2), M)
