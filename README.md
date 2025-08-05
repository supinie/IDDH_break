# Post-Quantum Security of the Inverse Discrete Logarithm Problem

This repository contains the implementation to accompany [2025/1417](https://ia.cr/2025/1417).

It is forked from https://github.com/AdamaSoftware/InverseDiscrete, with `IDDE.py`, `IDDH.py`, `IDKE.py`, `IDSA.py` from the original author.

We add `attack.py` showing how an oracle for the discrete logarithm problem can be used to solve the inverse discrete logarithm problem as proposed in [2025/1391](https://eprint.iacr.org/2025/1391).

We note that firstly, a value of `d = 2` is hard-coded in the attack for the given parameter set (though this is not a restriction); as well as only the functions from `IDDH.py` are imported for use in `attack.py`, however key generation remains the same amongst all implementations, and so our proof of concept works for all.
