### Produce forgeries for Origami-128


import ctypes as C
import os

# Import the lib 
lib = C.CDLL("./lib/libOrigami-128.so")

genkeys = lib.sig_keygen
genkeys.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
genkeys.restype = C.c_int

PK_BYTES = 2996
SK_BYTES = 16
SEED_BYTES = 16

pk   = C.create_string_buffer(PK_BYTES)
sk   = C.create_string_buffer(SK_BYTES)
seed = C.create_string_buffer(os.urandom(SEED_BYTES))
pk_len = C.c_ulonglong()
sk_len = C.c_ulonglong()

verify = lib.sig_verify
verify.argtypes = [
    C.c_void_p, C.c_ulonglong,
    C.c_void_p, C.c_ulonglong,
    C.c_void_p, C.c_ulonglong
]
verify.restype = C.c_int

# Run KeyGen
assert genkeys(pk, C.byref(pk_len), sk, C.byref(sk_len)) == 0
public_key = pk.raw.hex().upper()
print("PK:",public_key)
# Redact the secret key
C.memset(sk, 0, SK_BYTES)
# Pick a message
message = "Origami".encode("utf-8").hex().upper()
print("Message:", message)

# Load and run the sage attack
load("forge.sage") 
forgery = forge(public_key, message)
forged_hex = forgery.hex().upper()
print("Forgery:", forged_hex)

# Use the library's verify
msg = bytes.fromhex(message)
sig = C.create_string_buffer(forgery)
msg_buf = C.create_string_buffer(msg)

assert verify(
    pk, pk_len.value,
    sig, len(forgery),
    msg_buf, len(msg)
) == 0
print("Forgery verified")
