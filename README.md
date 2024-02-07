# Read the full blog post here

https://www.zellic.io/blog/mpc-from-scratch/

# MPC from Scratch

A toy, educational implementation of [Garbled Circuit protocol](https://en.wikipedia.org/wiki/Garbled_circuit) from scratch in Python

Note: this uses TEXTBOOK cryptography and textbook RSA for illustrative purposes. Don't use it in production

Circuit synthesis is done using Yosys. It synthesizes circuit.v (high level logic) into out.v which is only gate level logic. Then the MPC implementation uses a hacky Verilog parser to get the circuit
