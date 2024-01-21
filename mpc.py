import os
import random

from Crypto.Util.number import getRandomNBitInteger, getPrime, long_to_bytes, bytes_to_long
from Crypto.Hash import SHA3_256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Primality testing
def rabin_miller(n, k=40):
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

SMALL_PRIMES = list(map(int, map(str.strip, open('primes.txt','r').readlines()))) # gen with sieve.py
def rabin_miller_fast(n, k=40):
    for p in SMALL_PRIMES:
        if n % p == 0:
            return False
    return rabin_miller(n, k)


def randbits(n):
    return getRandomNBitInteger(n)

def gen_prime(n):
    while True:
        p = randbits(n)
        p |= 1 # we only want odd numbers
        if rabin_miller_fast(p):
            return p
        print('.', end='', flush=True)

def gen_prime_fast(n):
    return getPrime(n, os.urandom)

gen_prime = gen_prime_fast

def egcd(aa, bb):
    lr, r = abs(aa), abs(bb)
    x, lx, y, ly = 0, 1, 1, 0
    while r:
        lr, (q, r) = r, divmod(lr, r)
        x, lx = lx - q*x, x
        y, ly = ly - q*y, y
    return lr, lx * (-1 if aa < 0 else 1), ly * (-1 if bb < 0 else 1)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError
    return x % m

def gen_rsa_params(n=2048):
    p, q = gen_prime(n//2), gen_prime(n//2)
    N = p * q
    e = 65537
    phi = (p-1)*(q-1)
    d = modinv(e, phi)
    return e,d,N

# note: textbook rsa has issues, padding should be used

def oblivious_transfer_alice(m0, m1, n=2048, e=None, d=None, N=None):
    # generate new rsa parameters if not specified, otherwise use provided
    if e is None or d is None or N is None:
        e, d, N = gen_rsa_params(n)

    if m0 >= N or m1 >= N:
        raise ValueError('N too low')
    yield (e, N)
    x0, x1 = randbits(n), randbits(n)
    v = yield (x0, x1)
    k0 = pow(v - x0, d, N)
    k1 = pow(v - x1, d, N)
    m0k = (m0 + k0) % N
    m1k = (m1 + k1) % N
    yield m0k, m1k

def oblivious_transfer_bob(b, n=2048):
    if not b in (0, 1):
        raise ValueError('b must be 0 or 1')
    e, N = yield
    x0, x1 = yield
    k = randbits(n)
    v = ((x0, x1)[b] + pow(k, e, N)) % N
    m0k, m1k = yield v
    mb = ((m0k, m1k)[b] - k) % N
    yield mb

# 1-2 oblivious transfer
def oblivious_transfer(alice, bob):
    e, N = next(alice)
    next(bob)
    bob.send((e, N))

    x0, x1 = next(alice)
    v = bob.send((x0, x1))

    m0k, m1k = alice.send(v)

    mb = bob.send((m0k, m1k))
    return mb


# quick and dirty verilog parser
def parse_verilog(filename):
    circuit = {} # map from wire name -> (gate, name of the wires that are inputs to the gate...)
    inputs = []
    outputs = []
    import re
    filecontents = open(filename, 'r').read()
    for l in filecontents.split(';'):
        if not l: continue
        l = re.sub(r"/\*.*?\*/", '', l, flags=re.DOTALL) # remove comments
        l = re.sub(r'//.*$', '', l, flags=re.MULTILINE) # remove comments
        l = l.strip()
        tokens = l.split(' ')
        if tokens[0] == 'module': continue
        if tokens[0] == 'endmodule': continue
        tokens[-1] = tokens[-1].rstrip(';')
        if tokens[0] in ('wire', 'output', 'input'): # declaration
            if len(tokens) != 2:
                raise ValueError('unsupported statement:', l)
            typ, name = tokens
            if typ == 'input':
                inputs.append(name)
            elif typ == 'output':
                outputs.append(name)
            circuit[name] = None
        elif tokens[0] == 'assign': # assignment
            if tokens[2] != '=':
                raise ValueError('unsupported statement:', l)
            lhs = tokens[1]
            if '[' in lhs or ':' in lhs:
                raise ValueError('unsupported statement:', l)
            rhs = [*filter(bool,re.split(r'\b',''.join(tokens[3:])))]
            match rhs:
                case ['~', var]:
                    rhs = ('not', var)
                case [var1, '&', var2]:
                    rhs = ('and', var1, var2)
                case [var1, '|', var2]:
                    rhs = ('or', var1, var2)
                case [var1, '^', var2]:
                    rhs = ('xor', var1, var2)
                case [var1, '|~(', var2, ')']:
                    rhs = ('ornot', var1, var2)
                case [var1, '&~(', var2, ')']:
                    rhs = ('andnot', var1, var2)
                case ['~(', var1, '&', var2, ')']:
                    rhs = ('nand', var1, var2)
                case ['~(', var1, '|', var2, ')']:
                    rhs = ('nor', var1, var2)
                case ['~(', var1, '^', var2, ')']:
                    rhs = ('xnor', var1, var2)
                case ['1', "'", val]:
                    if not re.match(r'h(0|1)', val):
                        raise ValueError('unsupported statement:', l)
                    rhs = ('const_' + val[1],)
                case _:
                    raise ValueError('unsupported statement:', l)
            circuit[lhs] = rhs
            for var in rhs[1:]:
                if var not in circuit:
                    raise ValueError('undefined variable:', var, 'in statement', l)
        else:
            raise ValueError('unsupported statement:', l)
    for wire, value in circuit.items():
        if not value and wire not in inputs:
            raise ValueError('wire was never assigned:', wire)
    return circuit, inputs, outputs

import itertools
import functools
import operator

def label_truth_table(output_name, gate, input_names, labels, k=128):
    if gate == 'and':
        assert len(input_names) == 2
        logic_table = [[0, 0], [0, 1]]
    elif gate == 'or':
        assert len(input_names) == 2
        logic_table = [[0, 1], [1, 1]]
    elif gate == 'nand':
        assert len(input_names) == 2
        logic_table = [[1, 1], [1, 0]]
    elif gate == 'xnor':
        assert len(input_names) == 2
        logic_table = [[1, 0], [0, 1]]
    elif gate == 'xor':
        assert len(input_names) == 2
        logic_table = [[0, 1], [1, 0]]
    elif gate == 'ornot':
        assert len(input_names) == 2
        logic_table = [[1, 0], [1, 1]]
    elif gate == 'nor':
        assert len(input_names) == 2
        logic_table = [[1, 0], [0, 0]]
    elif gate == 'andnot':
        assert len(input_names) == 2
        logic_table = [[0, 0], [1, 0]]
    elif gate == 'not':
        assert len(input_names) == 1
        logic_table = [1, 0]
    elif gate == 'const_0':
        assert len(input_names) == 0
        logic_table = 0
    elif gate == 'const_1':
        assert len(input_names) == 0
        logic_table = 1
    else:
        raise ValueError('unsupported gate', gate)
    for var in (output_name, *input_names):
        if var not in labels:
            labels[var] = [randbits(k), randbits(k)] # 0 and 1 labels for each var
    labeled_table = []
    for inp_values in itertools.product((0,1), repeat=len(input_names)):
        output_value = functools.reduce(operator.getitem, inp_values, logic_table)
        output_label = labels[output_name][output_value]
        input_labels = [labels[input_name][input_value] for input_name, input_value in zip(input_names, inp_values)]
        labeled_table.append((output_label, input_labels))
    return labeled_table

def combine_keys(keys, k=128):
    h = SHA3_256.new()
    for ki in keys:
        h.update(long_to_bytes(ki))
    return h.digest()

def symmetric_enc(key, x):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(pad(long_to_bytes(x), 16))
    nonce = cipher.nonce
    return ciphertext, tag, nonce

def symmetric_dec(key, ciphertext, tag, nonce):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    x = bytes_to_long(unpad(cipher.decrypt_and_verify(ciphertext, tag), 16))
    return x

def garble_table(labeled_table):
    result = []
    for row in labeled_table:
        output_label, input_labels = row
        key = combine_keys(input_labels)
        c, tag, nonce = symmetric_enc(key, output_label)
        result.append((c, tag, nonce))
    random.shuffle(result) # this isn't a secure shuffle
    return result

def topoorder(circuit, inputs, outputs):
    postorder = []
    visited = set()
    def visit(wire_name):
        if wire_name in visited:
            return
        visited.add(wire_name)
        if wire_name not in inputs:
            gate, *input_wire_names = circuit[wire_name]
            for input_wire in input_wire_names:
                visit(input_wire)
        postorder.append(wire_name)
    for input_wire in outputs:
        visit(input_wire)
    return postorder # note: dont need to reverse for topo b.c nodes point to their dependencies

def garble_circuit(circuit, inputs, outputs, k=128):
    labels = {}
    garbled_tables = []
    
    # we topologically order all the wires. there is a valid topological ordering because circuits are acyclic.
    # by ordering the wires, we can use the indices as unique ids to refer to each wire
    wires = topoorder(circuit, inputs, outputs)
    wire_index = {wire: i for i, wire in enumerate(wires)}

    for wire_name in wires:
        if wire_name in inputs:
            print('input wire:', wire_name)
            garbled_tables.append((None, None)) # this is an input wire, just add a palceholder value
            continue
        gate, *input_wire_names = circuit[wire_name]
        print(wire_name, gate, input_wire_names)
        labeled_table = label_truth_table(wire_name, gate, input_wire_names, labels, k)
        garbled_table = garble_table(labeled_table)

        input_wire_indexes = [wire_index[input_wire] for input_wire in input_wire_names]
        assert all(i < len(garbled_tables) for i in input_wire_indexes)
        garbled_tables.append((garbled_table, input_wire_indexes))
    
    assert len(garbled_tables) == len(wires)

    return garbled_tables, labels, wire_index

def eval_garbled_circuit(garbled_tables, circuit_input_labels, output_wire_indexes):
    evaluated_gates = [] # holds an array of the output wire's decrypted label as we progressively evaluate the circuit

    for i, (garbled_table, input_wire_indexes) in enumerate(garbled_tables):
        if i in circuit_input_labels: # this is an input wire
            evaluated_gates.append(circuit_input_labels[i])
            continue

        for row in garbled_table:
            c, tag, nonce = row
            gate_input_labels = [evaluated_gates[index] for index in input_wire_indexes]
            key = combine_keys(gate_input_labels)
            try:
                output_label = symmetric_dec(key, c, tag, nonce)
            except ValueError: # incorrect padding
                continue
            evaluated_gates.append(output_label)
            break
        else:
            raise ValueError('unable to decrypt garbled table', i)
        
        print('evaluated gate', i, '=', output_label)

    assert len(evaluated_gates) == len(garbled_tables)

    output_labels = [evaluated_gates[i] for i in output_wire_indexes]
    return output_labels

def wire_values(wire_name, value, bitsize):
    bits = bin(value)[2:].zfill(32)
    return {f"{wire_name}_{i}": int(bit) for i, bit in enumerate(reversed(bits))}

# X is alice's input
# x = number of bits in the input wire 'x' in the circuit
# y = number of bits in the input wire 'y' in the circuit
# n = RSA security bits
# k = garbled circuits security bits (label size)
def garbled_circuit_alice(circuits, input_wires, output_wires, X, x_bits=32, y_bits=32, n=2048, k=128):
    garbled_tables, labels, wire_index = garble_circuit(circuit, input_wires, output_wires)
    output_indexes = [wire_index[wire] for wire in output_wires]

    # {wire_name: [label_0, label_1], ...} -> {label_0: wire_name=0, label_1: wire_name=1, ...}
    labels_to_names = dict((v, k + '=' + str(i)) for k, v01 in labels.items() for i, v in enumerate(v01))
    for k, v in labels_to_names.items(): print(k, '\t', v)

    # setup Alice's input wires
    alice_input_values = {**wire_values('x', X, x_bits)}
    print('alice input values:', alice_input_values)

    # map of wire_index -> given label (for alice's wires)
    alice_input_labels = {wire_index[wire]: labels[wire][alice_input_values[wire]] for wire in input_wires if wire.startswith('x_')}

    # bob also needs to know which wires are his inputs
    bob_input_indexes = [wire_index[f'y_{i}'] for i in range(y_bits)]
    # setup the oblivious transfer for bob's input wires
    ot_alices = []
    e, d, N = gen_rsa_params(n)
    for i in range(y_bits):
        m0, m1 = labels[f'y_{i}'] # get the 0 and 1 labels for bob's input wire 'y'
        ot_alices.append(oblivious_transfer_alice(m0, m1, n, e, d, N))

    # send parameters to bob and do the oblivious transfer. Bob will reply back with his output labels
    output_labels = yield labels, garbled_tables, alice_input_labels, bob_input_indexes, output_indexes, ot_alices

    # convert the labels back to plain values
    output = [labels_to_names[label] for label in output_labels]
    yield output

# Y is bob's input
# input_bits = number of bits in the input wire 'y' in the circuit
def garbled_circuit_bob(Y, y_bits=32, n=2048, k=128):
    bob_input_values = {**wire_values('y', Y, y_bits)}
    print('bob input values:', bob_input_values)

    # setup the oblivious transfer for bob's input wires
    ot_bobs = [oblivious_transfer_bob(bob_input_values[f'y_{i}'], n) for i in range(y_bits)]

    # do the oblivious transfer now. Also, receive the rest of alice's parameters
    garbled_tables, alice_input_labels, bob_input_indexes, output_indexes, bob_input_labels = yield ot_bobs
    assert len(bob_input_indexes) == y_bits and len(bob_input_labels) == y_bits

    # boilerplate, go from a list of label values to a dict from wire to label
    bob_input_labels = dict(zip(bob_input_indexes, bob_input_labels))
    
    # now we have all the input labels
    input_labels = {**alice_input_labels, **bob_input_labels}
    print('input labels:', input_labels)

    output_labels = eval_garbled_circuit(garbled_tables, input_labels, output_indexes)
    yield output_labels

if __name__ == '__main__':
    # build with ./oss-cad-suite/bin/yosys -s yosys-script.txt
    circuit, input_wires, output_wires = parse_verilog('out.v')

    X = 9001
    Y = 1337

    # setup
    gc_alice = garbled_circuit_alice(circuit, input_wires, output_wires, X, x_bits=32, y_bits=32)
    gc_bob = garbled_circuit_bob(Y, y_bits=32)

    # alice garbles the circuit and prepares for an oblivious transfer of bob's input labels
    labels, garbled_tables, alice_input_labels, bob_input_indexes, output_indexes, ot_alices = next(gc_alice)
    # bob prepares for an oblivious transfer of all his input labels
    ot_bobs = next(gc_bob)

    # do the oblivious transfer of all of bobs input wire bits
    bob_input_labels = [oblivious_transfer(alice, bob) for alice, bob in zip(ot_alices, ot_bobs)]
    print('bob input labels:', bob_input_labels)
    # Send bob all the other params from Alice too
    # then Bob will run the garbled circuit
    output_labels = gc_bob.send((garbled_tables, alice_input_labels, bob_input_indexes, output_indexes, bob_input_labels))
    print('output labels:', output_labels)

    # give output labels to alice to get final output
    output = gc_alice.send(output_labels)
    for val in output:
        print(val)

    exit()

