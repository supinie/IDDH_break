from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256
from secrets import randbelow as randint
import os

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
    shared_bytes = data.to_bytes((data.bit_length() + 7) // 8, 'big')
    return sha256(shared_bytes).digest()

def encrypt(pk, pt):
    pks, sks = keygen()
    shared_secret = pow(pk, sks, m)
    key = hash(shared_secret)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, pt, None)
    return (pks, nonce+ct)

def decrypt(sk, ct):
    pks, body = ct
    shared_secret = pow(pks, sk, m)
    key = hash(shared_secret)
    aesgcm = AESGCM(key)
    nonce = body[:12]
    ctm = body[12:]
    M = aesgcm.decrypt(nonce, ctm, None)
    return M
pk, sk = keygen()
msg = b"Hello world!"
print("PT:", msg)
body = encrypt(pk, msg)
print("CT:", body)

pt = decrypt(sk, body)
print("PT:", pt)
