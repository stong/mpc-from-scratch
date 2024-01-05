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

def randbits(n):
	return random.randrange(2**(n-1), 2**n-1)

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
	circuit = {} # map from wire name -> (gate, gate operands...)
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
					rhs = ('const', int(val[1]))
				case _:
					raise ValueError('unsupported statement:', l)
			circuit[lhs] = rhs
			if rhs[0] != 'const':
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


def garbled_circuit(n=2048, k=128):
	parse_verilog('out.v')
	pass

if __name__ == '__main__':
	garbled_circuit()
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

