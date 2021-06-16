# Introduction

[angr](https://angr.io/) is a Python library to perform higher-level symbolic
execution tasks e.g. vs [z3](../z3). It does more than that of course, read
the docs!

# Usage

Code was adapted from the [very good Angr CTF exercises](https://github.com/jakespringer/angr_ctf)
and tested with Angr 9.0 and Python 3.9.5.

`solve.py` shows how to extract the flag by instructing angr to explore and find a
solution that reaches the success address and avoiding the failure address.

# References

- [Angr CTF exercises](https://github.com/jakespringer/angr_ctf) - One of the
  best ways to learn Angr by doing, see [my Angr9/Python3 solutions](../../angr-ctf-solutions).

