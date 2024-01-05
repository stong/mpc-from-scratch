import random

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

SMALL_PRIMES = list(map(int, map(str.strip, open('primes.txt','r').readlines())))
def rabin_miller_fast(n, k=40):
	for p in SMALL_PRIMES:
		if n % p == 0:
			return False
	return rabin_miller(n, k)

import Crypto.Util.number

def randbits(n):
	return random.randrange(2**(n-1), 2**n-1) # todo: replace with Crypto.Util.number.getRandomNBitInteger(n)

def gen_safe_prime(n):
	while True:
		# generate n-2 bits, always make the last 2 bits 11 (even numbers aren't prime
		# also we want a safe prime and safe primes are always 3 mod 4
		p = randbits(n-2)
		p = 4 * p + 3
		if not rabin_miller_fast(p): # primality test
			print('.', end='', flush=True)
			continue
		if not rabin_miller((p - 1) // 2): # test for safe prime
			print('+', end='', flush=True)
			continue
		return p

def gen_safe_prime_fast(n):
	from Crypto.Util import number
	import os
	return number.getPrime(n, os.urandom)

gen_safe_prime = gen_safe_prime_fast

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
	p, q = gen_safe_prime(n//2), gen_safe_prime(n//2)
	N = p * q
	e = 65537
	phi = (p-1)*(q-1)
	d = modinv(e, phi)
	return e,d,N

# note: textbook rsa has issues, padding should be used

def oblivious_transfer_alice(m0, m1, n=2048):
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
				case ['1', "'", val]:
					if not re.match(r'h(0|1)', val):
						raise ValueError('unsupported statement:', l)
					rhs = ('const_' + val[1])
				case _:
					raise ValueError('unsupported statement:', l)
			circuit[lhs] = rhs
			for var in rhs[1:]:
				if var not in circuit:
					raise ValueError('undefined variable:', var)
			# print(lhs,rhs)
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
	else:
		raise ValueError('unsupported gate', gate)
	for var in (output_name, *input_names):
		if var not in labels:
			labels[var] = [randbits(k), randbits(k)] # 0 and 1 labels for each var
	labeled_table = []
	for inp_values in itertools.product((0,1), repeat=len(input_names)):
		output_value = functools.reduce(operator.getitem, inp_values, logic_table)
		output_label = labels[output_name][output_value]
		input_labels = [labels[input_names[i]][v] for i, v in enumerate(inp_values)]
		labeled_table.append((output_label, input_labels))
	return labeled_table

def combine_keys(keys, k=128):
	from Crypto.Hash import SHA3_256
	h = SHA3_256.new()
	for ki in keys:
		h.update(ki.to_bytes(k//8, 'big'))
	return h.digest()

def symmetric_enc(keys, x, k=128):
	from Crypto.Cipher import AES
	from Crypto.Util.Padding import pad
	key = combine_keys(keys, k)
	cipher = AES.new(key, Crypto.Cipher.AES.MODE_CTR)
	c = cipher.encrypt(pad(x.to_bytes(k//8, 'big'), 16))
	nonce = cipher.nonce
	return c, nonce

def symmetric_dec(keys, c, nonce, k=128):
	from Crypto.Cipher import AES
	from Crypto.Util.Padding import unpad
	key = combine_keys(keys, k)
	cipher = AES.new(key, Crypto.Cipher.AES.MODE_CTR, nonce=nonce)
	x = unpad(cipher.decrypt(c), 16)
	return int.from_bytes(x, 'big')

def garble_table(labeled_table, k=128):
	result = []
	for row in labeled_table:
		output_label, input_labels = row
		c, nonce = symmetric_enc(input_labels, output_label, k)
		result.append((c, nonce))
	random.shuffle(result) # this isn't a secure shuffle
	return result

def topoorder(circuit, inputs, outputs):
	postorder = []
	visited = set()
	def visit(wire_name):
		print(wire_name)
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
			garbled_tables.append((None, None)) # this is an input wire, just add a palceholder value
			continue
		gate, *input_wire_names = circuit[wire_name]
		print(wire_name, gate, input_wire_names)
		labeled_table = label_truth_table(wire_name, gate, input_wire_names, labels, k)
		print(labeled_table)
		garbled_table = garble_table(labeled_table)
		print(garbled_table)

		input_wire_indexes = [wire_index[input_wire] for input_wire in input_wire_names]
		assert all(i < len(garbled_table) for i in input_wire_indexes)
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
			c, nonce = row
			gate_input_labels = [evaluated_gates[i] for i in input_wire_indexes]
			try:
				output_label = symmetric_dec(gate_input_labels, c, nonce)
			except ValueError: # incorrect padding
				continue
			print('evaluated gate', i, '=', output_label)
			evaluated_gates.append(output_label)
			break
		else:
			print('dont have this table')

	assert len(evaluated_gates) == len(garbled_tables)

	output_labels = [evaluated_gates[i] for i in output_wire_indexes]
	return output_labels


if __name__ == '__main__':
	circuit, inputs, outputs = parse_verilog('out.v')

	# alice does this
	garbled_tables, labels, wire_index = garble_circuit(circuit, inputs, outputs)

	# {wire_name: [label_0, label_1], ...} -> {label_0: wire_name=0, label_1: wire_name=1, ...}
	labels_to_names = dict((v, k + '=' + str(i)) for k, v01 in labels.items() for i, v in enumerate(v01))
	print(labels_to_names)
	
	input_values = {'x': 1, 'y': 1}
	# map of wire_index -> given label
	input_labels = {wire_index[wire]: labels[wire][input_values[wire]] for wire in inputs}

	output_indexes = [wire_index[wire] for wire in outputs]
	
	# bob does this
	output_labels = eval_garbled_circuit(garbled_tables, input_labels, output_indexes)
	print('output labels', output_labels)

	# alice does this
	output = [labels_to_names[label] for label in output_labels]
	print('final output', output)

	exit()

	m0 = 9001
	m1 = 1337

	alice = oblivious_transfer_alice(m0, m1)
	bob  = oblivious_transfer_bob(1)

	e, N = next(alice)
	next(bob)
	bob.send((e, N))

	x0, x1 = next(alice)
	v = bob.send((x0, x1))

	m0k, m1k = alice.send(v)

	mb = bob.send((m0k, m1k))

	print('mb', mb)

