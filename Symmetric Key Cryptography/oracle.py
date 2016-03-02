from aes import aes_encrypt, aes_decrypt

def submit(s, k, iv):
    # URL encodes the characters ';' and '='.
    s = s.replace(";", "%3B")
    s = s.replace("=", "%3D")

    # Append and prepend required strings.
    s = "userid=456;userdata=" + s
    s = s + ";session-id=31337"

    return aes_encrypt(s, k, "CBC", iv)

# Decrypts a string and returns true if the substring ";admin=true;" exists
# in the string.
def verify(c, k, iv):

    return ";admin=true;" in aes_decrypt(c, k, "CBC", iv)
