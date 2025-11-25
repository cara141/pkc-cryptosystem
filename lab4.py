import sympy


class RsaMachine:
    def __init__(self, alphabet: list[str]):
        self.alphabet = alphabet
        self.base = len(alphabet)

        # two random primes
        self.p = 31
        self.q = 43
        # product
        self.n = self.p * self.q
        # euler's totient
        self.phi = (self.p - 1) * (self.q - 1)
        # public exponent
        self.e = self._generate_e()
        # private exponent
        self.d = sympy.mod_inverse(self.e, self.phi)

        # block sizes
        self.plain_block = 2
        self.cipher_block = 3

    def _generate_e(self):
        while True:
            e = sympy.randprime(2, self.phi)
            if sympy.gcd(e, self.phi) == 1:
                return e

    def gen_public_key(self):
        return self.e, self.n

    def gen_private_key(self):
        return self.d, self.n

    def encode_block(self, chars):
        """Encode plaintext block into integer."""
        num = 0
        for ch in chars:
            num = num * self.base + self.alphabet.index(ch)
        return num

    def decode_block(self, num):
        """Decode plaintext integer."""
        chars = []
        for _ in range(self.plain_block):
            chars.append(self.alphabet[num % self.base])
            num //= self.base
        return ''.join(reversed(chars))

    def encode_cipher_block(self, num):
        """Encode RSA ciphertext number."""
        chars = []
        for _ in range(self.cipher_block):
            chars.append(self.alphabet[num % self.base])
            num //= self.base
        return ''.join(reversed(chars))

    def decode_cipher_block(self, chars):
        """Decode 3 ciphertext chars."""
        num = 0
        for ch in chars:
            num = num * self.base + self.alphabet.index(ch)
        return num

    def encrypt(self, plaintext, public_key):
        e, n = public_key
        # pad plaintext
        while len(plaintext) % self.plain_block != 0:
            plaintext += "_"

        ciphertext = ""

        for i in range(0, len(plaintext), self.plain_block):
            block = plaintext[i:i + self.plain_block]
            m = self.encode_block(block)
            c = pow(m, e, n)
            ciphertext += self.encode_cipher_block(c)

        return ciphertext

    def decrypt(self, ciphertext, private_key):
        d, n = private_key

        plaintext = ""

        for i in range(0, len(ciphertext), self.cipher_block):
            block = ciphertext[i:i + self.cipher_block]
            c = self.decode_cipher_block(block)
            m = pow(c, d, n)
            plaintext += self.decode_block(m)

        return plaintext


alphabet = ["_", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
            "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]

Rsa = RsaMachine(alphabet)

pub = Rsa.gen_public_key()
priv = Rsa.gen_private_key()

plaintext = "___abcdebla_bla_blaffffffff_blaghjkla_______________bla_"

cipher = Rsa.encrypt(plaintext, pub)
decrypted = Rsa.decrypt(cipher, priv)

try:
    assert decrypted == plaintext
    # print(f"Test passed on run {run}")
except AssertionError:
    print(f"Test failed: expected {plaintext}, got {decrypted}")
