from Crypto.Util.number import getPrime, inverse

def E():
    return 65537

def rsa_key_gen():
    p = getPrime(1024)
    q = getPrime(1024)

    n = p * q
    return [[E(), n], [inverse(E(), (p - 1) * (q - 1)),n]]

def rsa_encrypt(pk, m):
    return pow(m, pk[0], pk[1])

def rsa_decrypt(sk, c):
    return pow(c, sk[0], sk[1])

def rsa_malleability(pk, c):
    return rsa_encrypt(pk, 0) * c
