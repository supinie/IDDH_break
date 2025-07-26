from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256
from secrets import randbelow as randint
from secrets import token_bytes

m = 10634451920321482078832648660644891033089372515123531501204680131061388333606322960878246740400211061750125161245789054652565173977296881895208938982350997
phi_m = 10634451920321482078832648660644891033089372515123531501204680131061388333606116705845312366304081965897126257533927133313899564526534606369637669563592480
y = 3215089980925344446382473455174469618223070254520214482773528260567915137712971519748348208484290402351203777403060998117483282698426141723868715140824334
g = 3675935972974948820265758027860187521138308045338774076408141125423969618538593689156009959762130135662718666404667688507754622336235855838956454687428217

def keygen():
    sk = randint(phi_m - 3) + 2
    P_A = pow(g, sk, m)
    pk = pow(P_A, y, m)
    return pk, sk

def hash(data):
    return int.from_bytes(sha256(data).digest())

def sign(sk, msg):
    r = randint(phi_m - 1) + 1
    t = pow(g, r*y, m)
    e = hash(msg + t.to_bytes((t.bit_length() + 7) // 8, 'big')) % phi_m
    s = (r + e * sk) % phi_m
    return (t, s)

def verify(pk, msg, signature):
    t, s = signature
    e = hash(msg + t.to_bytes((t.bit_length() + 7) // 8, 'big')) % phi_m
    lhs = pow(g, s*y, m)
    rhs = (t * pow(pk, e, m)) % m
    return lhs == rhs

pk, sk = keygen()
msg = b"Hello, world!"
sig = sign(sk, msg)
valid = verify(pk, msg, sig)
print(valid)