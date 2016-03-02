from aes import aes_encrypt, aes_decrypt, BLOCK_SIZE
from Crypto.Util.number import getRandomNBitInteger
from Crypto.Hash import SHA256
from os import urandom

class DHUser:

    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.priv = getRandomNBitInteger(2048)

    def gen_pub(self):
        return pow(self.g, self.priv, self.p)

    def gen_shared_secret(self):
        self.secret = pow(self.other, self.priv, self.p)
        self.key = SHA256.new(str(self.secret)).digest()[:16]

    def other_pub(self, other):
        self.other = other

    def encrypt(self, m):
        self.iv = urandom(BLOCK_SIZE())
        return [aes_encrypt(m, self.key, "CBC", self.iv), self.iv]

    def decrypt(self, c, iv):
        return aes_decrypt(c, self.key, "CBC", iv)

def exchange_keys(alice, bob, mitm = False):

    if mitm:
        A = B = alice.p
    else:
        A = alice.gen_pub()
        B = bob.gen_pub()

    bob.other_pub(A)
    alice.other_pub(B)
    alice.gen_shared_secret()
    bob.gen_shared_secret()

def exchange_messages(alice, bob, silent = False):
    m_a = raw_input("Enter Alice's message to Bob: ")
    m_b = raw_input("Enter Bob's message to Alice: ")
    c_a = alice.encrypt(m_a)
    c_b = bob.encrypt(m_b)

    if not silent:
        print("Encrypted message " + c_b[0].encode("hex") 
                + " to Alice decrypts to: " + alice.decrypt(c_b[0], c_b[1]))
        print("Encrypted message " + c_a[0].encode("hex") 
                + " to Bob decrypts to: " + bob.decrypt(c_a[0], c_a[1]))

    return [c_a, c_b]

def verify_secret_gen(alice, bob):
    if alice.secret == bob.secret:
        print("Alice and Bob generated the same shared secret.")
    else:
        raise ValueError("Alice and Bob did not generate the same " 
                + "shared secret!")

def mitm_decrypt(mallory, c_a, c_b):
    print("Alice's message to Bob " + c_a[0].encode("hex") 
            + " decrypted by " + "Mallory: " 
            + mallory.decrypt(c_a[0], c_a[1]))
    print("Bob's message to Alice " + c_b[0].encode("hex") 
            + " decrypted by " + "Mallory: " 
            + mallory.decrypt(c_b[0], c_b[1]))
