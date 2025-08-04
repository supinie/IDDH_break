from functools import partial
from IDDH import *

m = 7875195248299573808823712291978888274442999959677694753912571847780087214002722858683689069525773011732211611836327013706360435849189331163147852550661829
phi_m = 7875195248299573808823712291978888274442999959677694753912571847780087214002545356037534989272459012221013085436360316370101093947233788503313425120303276
y = 6299229908833840118619829672945751411735622605656289025512914596518177159383400059722142269040719786180255780735904363854210629937073277010069155086020014
g = 3052880011133317644565832334485921658988691008053236805842669552104284584971658329333569136294140088171228312120170305145176435676513862646086102301423957

def shor_oracle(base, target, x):
    return (2 * x) % phi_m

def find_x(x_prime, A):
    if phi_m == m:
        for k in range(0, 3):
            candidate = (x_prime - k) // 2
            if pow(g, candidate * y, m) == A:
                return candidate
    else:
        for k in range(0, 3):
            candidate = (x_prime + k * (phi_m - m)) // 2
            if pow(g, candidate * y, m) == A:
                return candidate
    print("FAILED TO FIND X")

def main():
    (A, x) = keygen()
    instance_oracle = partial(shor_oracle, x = x)

    y_prime = y // 2

    base = pow(g, y_prime, m)

    x_prime = instance_oracle(base, A)

    x_found = find_x(x_prime, A)

    print("x:     ", x)
    print("found: ", x_found)
    assert pow(g, x_found * y, m) == A, "attack failed to successfully recover secret"
    print("attack successfully recovered secret")

main()
