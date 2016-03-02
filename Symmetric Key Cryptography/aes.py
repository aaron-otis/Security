from Crypto.Cipher import AES
from utils import pkcs7_pad, strip_padding, xor

def BLOCK_SIZE():
    return 16

# AES encrypts a string. Supports ECB and CBC modes only.
def aes_encrypt(m, k, mode, iv = None):
    aes = AES.new(k, AES.MODE_ECB)
    c = ""

    # Add padding
    if len(m) % BLOCK_SIZE() != 0:
        m = m + pkcs7_pad(len(m), BLOCK_SIZE())

    if mode == "CBC": 
        if iv is None:
            raise ValueError("CBC mode requires an IV.")
        else:
            for i in range(0, len(m), BLOCK_SIZE()):
                block = xor(m[i:i + BLOCK_SIZE()], iv)
                iv = aes.encrypt(block)
                c = c + iv
            return c
    elif mode == "ECB":
        for i in range(0, len(m), BLOCK_SIZE()):
            c = c + aes.encrypt(m[i:i + BLOCK_SIZE()])
        return c
    else:
        raise ValueError("Incorrect mode used: " + mode)

# AES decrypts a string. Supports ECB and CBC modes only.
def aes_decrypt(c, k, mode, iv = None):
    aes = AES.new(k, AES.MODE_ECB)
    m = ""

    if mode == "CBC":
        if iv is None:
            raise ValueError("CBC mode requires and IV.")
        else:
            for i in range(0, len(c), BLOCK_SIZE()):
                block = aes.decrypt(c[i:i + BLOCK_SIZE()])
                m = m + xor(block, iv)
                iv = c[i:i + BLOCK_SIZE()]
            return strip_padding(m)
    elif mode == "ECB":
        for i in range(0, len(c), BLOCK_SIZE()):
            m = m + aes.encrypt(c[i:i + BLOCK_SIZE()])
        return strip_padding(m)
    else:
        raise ValueError("Incorrect mode used: " + mode)
