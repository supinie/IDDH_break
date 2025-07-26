from hashlib import sha256
from secrets import randbelow
from Crypto.Util.number import GCD, getPrime

p = getPrime(256)
q = getPrime(256)
m = p * q
phi_m = (p - 1) * (q - 1)

def randint(ep, sp):
    return randbelow(sp-ep) + ep
while True:
    y = randint(2, phi_m - 1)
    if GCD(y, phi_m) != 1:
        break

g = randint(2, m - 1)

def keygen(m, phi_m, y):
    sk = randint(2, phi_m - 1)
    P_A = pow(g, sk, m)
    pk = pow(P_A, y, m)
    return pk, sk

def hash(data):
    shared_bytes = data.to_bytes((data.bit_length() + 7) // 8, 'big')
    return sha256(shared_bytes).digest()

def exchange(sks, pkp):
    ss = pow(pkp,sks,m)
    return hash(ss)

pkA, skA = keygen(m, phi_m, y)
pkB, skB = keygen(m, phi_m, y)

ssA = exchange(skA, pkB)
ssB = exchange(skB, pkA)

assert ssA == ssB
print("SS:", ssA)