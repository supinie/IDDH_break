from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha512
from secrets import randbelow as randint
from secrets import token_bytes

m = 7875195248299573808823712291978888274442999959677694753912571847780087214002722858683689069525773011732211611836327013706360435849189331163147852550661829
phi_m = 7875195248299573808823712291978888274442999959677694753912571847780087214002545356037534989272459012221013085436360316370101093947233788503313425120303276
y = 6299229908833840118619829672945751411735622605656289025512914596518177159383400059722142269040719786180255780735904363854210629937073277010069155086020014
g = 3052880011133317644565832334485921658988691008053236805842669552104284584971658329333569136294140088171228312120170305145176435676513862646086102301423957

def keygen():
    sk = randint(phi_m - 3) + 2
    P_A = pow(g, sk, m)
    pk = pow(P_A, y, m)
    return pk, sk

def hash(data):
    return int.from_bytes(sha512(data).digest())

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
