from Crypto.Random import random
import challenge21
import time

t = int(time.time())
t += random.randint(40, 1000)
seed = int(t)
print(seed)
rng = challenge21.MT19937(seed)
x = rng.uint32()
print(x)
# TODO(akalin): Infer seed from x.
