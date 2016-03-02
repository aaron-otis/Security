from os import urandom

def xor(m, k):
    
    if len(m) != len(k): # Both inputs must be the same length.
        raise ValueError("Strings must be the same length to XOR.")

    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(m, k))

def encrypt_file(filename, header, key, mode = None, iv = None):
    f = open(filename, "rb").read()

    if mode is None:
        prefix = "otp_"
    else:
        prefix = "aes_" + mode + "_"

    c = open(prefix + filename, "wb")
    if mode is None:
        c.write(header + xor(f, key)[len(header):])
    else:
        from aes import aes_encrypt
        c.write(header + aes_encrypt(f, key, mode, iv)[len(header):])

    c.close()
    print("Encrypted file written to '" + prefix + filename + "'")

def find_collision(bits):
    from Crypto.Hash import SHA256
    from time import clock

    collision = []
    table = {}
    runtime = clock()

    while len(collision) == 0:
        m = urandom(32)
        sha_hash = SHA256.new(m).digest()
        size = int(bits / 8)

        if (bits % 8) > 0:
            size = size + 1

        sha_hash = sha_hash[0:size]
        sha_hash = sha_hash[:size - 1] + chr(ord(sha_hash[size - 1]) 
                & (0xFFFFFFFF << (8 - (bits % 8))))

        if sha_hash in table and table[sha_hash] != m:
            collision = [bits, clock() - runtime, len(table) + 1, 
                    {str(sha_hash).encode("hex") : 
                    [str(table[sha_hash]).encode("hex"), str(m).encode("hex")]}]
            table.clear()
            return collision
        else:
            table.update({sha_hash : m})

# Pads a string via PKCS#7 padding to the correct block size.
def pkcs7_pad(length, div):
    pad = ""

    for i in range(0, div - (length % div)):
        pad = pad + chr(div - (length % div))

    return pad

def strip_padding(m):
    from aes import BLOCK_SIZE

    if ord(m[-1:]) <= BLOCK_SIZE() and ord(m[-1:]) > 0:
        return m[:-ord(m[-1:])]
    else:
        return m
