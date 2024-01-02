import math
wow = [2]
for i in range(3,2000000):
	is_prime = True
	for p in wow:
		if p > int(math.sqrt(i)) + 1 or p > i:
			break

		if i % p == 0:
			is_prime = False
			break
	if is_prime:
		wow.append(i)
		print(i)
