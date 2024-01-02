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

def gen_safe_prime(n):
	while True:
		# generate n-2 bits, always make the last 2 bits 11 (even numbers aren't prime
		# also we want a safe prime and safe primes are always 3 mod 4
		p = random.randrange(2**(n-3)+1, 2**(n-2)-1)
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
	p = gen_safe_prime(n//2)
	q = gen_safe_prime(n//2)
	N = p * q
	e = 65537
	phi = (p-1)*(q-1)
	g, _, _ = egcd(phi, e) # ensure phi and e are coprime
	assert g == 1
	d = modinv(e, phi)
	return e,d,N

def oblivious_transfer(m0, m1, e, d, N):
	

if __name__ == '__main__':
	e, d, N = gen_rsa_params(2048)
	print(e,d,N)
