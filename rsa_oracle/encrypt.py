# %%
from typing import Optional

from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes

e = 65537


import random


def _is_probable_prime(n: int, rounds: int = 5) -> bool:
    """Return True if ``n`` passes a Miller-Rabin primality test."""
    if n in (2, 3):
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Write n-1 as d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def get_prime(bits: int, rng: random.Random | None = None) -> int:
    if rng is None:
        rng = random.Random()

    while True:
        candidate = rng.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def get_primes(bits: int):
    return get_prime(bits), get_prime(bits)


def gen_key(k):
    """
    Generates RSA key with k bits
    """
    p, q = get_primes(k // 2)
    N = p * q
    d = inverse(e, (p - 1) * (q - 1))

    return ((N, e), d)


def encrypt(pubkey, m):
    N, e = pubkey
    return pow(bytes_to_long(m.encode("utf-8")), e, N)


def main(flag):
    pubkey, _privkey = gen_key(1024)
    encrypted = encrypt(pubkey, flag)
    return (pubkey[0], encrypted)


if __name__ == "__main__":
    flag = "Hello world!"
    flag = flag.strip()
    N, cypher = main(flag)
    print("N:", N)
    print("e:", e)
    print("cyphertext:", cypher)

#%%
def create_string_from_long(x):
    return long_to_bytes(x).decode('latin-1')

def create_long_from_string(x):
    return int.from_bytes(x.encode('latin-1'), 'big')
# %%
class Point:
    def __init__(self, b):
        self.bytes = b
    
    def as_int(self):
        return int.from_bytes(self.bytes, 'big')
    
    def decoded(self):
        return self.bytes.decode('latin-1')
    
    def midpoint(self, other):
        inta = self.as_int()
        intb = other.as_int()

        newint = (inta + intb)//2
        newpoint = Point(long_to_bytes(newint))
        return newpoint

    def newlineloc(self):
        return self.bytes.find(b'\n')
    
    def removenewlines(self, toright=True):
        ba = bytearray(self.bytes)
        if toright:
            newchar = 11
            others = 0
        else:
            newchar = 9
            others = 254
            
        if (loc := self.newlineloc()) != -1:
            ba[loc] = newchar
            for i in range(loc + 1, len(ba)):
                ba[i] = others

        return Point(bytes(ba))



class Solver:
    def __init__(self, downloader):
        self.downloader = downloader

    def get_midpoint(self, start: Point, end: Point) -> Optional[Point]:
        sint = start.as_int()
        eint = end.as_int()

        if sint >= eint:
            raise ValueError("SAME")
        elif eint - sint < 2:
            print("Done")
            return None

        mid = start.midpoint(end)
        mid2 = mid.removenewlines()
        mint = mid2.as_int()
        if mint <= sint or mint >= eint:
            mid2 = mid.removenewlines(False)
            mint = mid2.as_int()
            if mint <= sint or mint >= eint:
                print("NO LUCK!")
                return None

        return mid2

    def get_new_start_end(self, start: Point, end: Point) -> Optional[Point]:
        mid = self.get_midpoint(start, end)
        if mid is None:
            return None

        msg = mid.decoded()
        mint = mid.as_int()
        mhex = hex(mint)[2:]
        encrypted_value = self.downloader.get_encryption(msg,version='text')
        oracle_hex = self.downloader.get_encryption(msg,version='hex')
        decrypted_message = self.downloader.get_decryption(encrypted_value, version='hex')
        if oracle_hex is None or decrypted_message is None or encrypted_value is None:
            print("GOT A NONE MATE")
            return None

        if oracle_hex != mhex:
            print("WARNING. OG HEXES DO NOT MATCH UP.")
            return None

        if mhex == decrypted_message:
            print('⬆️')
            return mid, end
        else:
            if mhex[:8] == decrypted_message[:8]:
                print("WARNING: GOT OVERLAP BUT NOT FULL")
                return None
            print('⬇️')
            return start, mid


#%%
downloader = Downloader(None)
solver = Solver(downloader=downloader)

#%%
start = Point(long_to_bytes(90) * 64)
end = Point(long_to_bytes(255) * 64)

for i in range(2):
    res = solver.get_new_start_end(start, end)
    if res is None:
        break

    start, end = res
    print(len(bin(end.as_int() - start.as_int())[2:]))
print(start.decoded())
print(end.decoded())
#%%
print(end.as_int() - start.as_int())
start.as_int()
#%%

N = end.as_int() # N = 5507...7971

#%%
# The plaintext string we will use as our blinding factor
S_pt = Point(long_to_bytes(2))
S_pt.bytes
#%%
# Convert the string to bytes (using standard UTF-8), then to an integer
# The 'big' means it's a big-endian conversion, which is standard.
S_int = S_pt.as_int()
S_str = S_pt.decoded()
# This will correctly set S_int to 50
print(f"The string '{S_str}' encodes to the integer: {S_int}")

#%%
encrypted_value = downloader.get_encryption(chr(2))
my_c_S = pow(S_int, e, N)
encrypted_value
print(my_c_S)
print(encrypted_value)

#%%
with open('secret.enc', 'r') as f:
    password = f.read().replace('\n', '') # password = 3567...8003
c_new = (password * int(encrypted_value)) % N
decr = downloader.get_decryption(str(c_new), 'hex')

#%%
long_to_bytes(int(decr, 16)//2).decode('latin-1')
