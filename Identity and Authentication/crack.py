from Crypto.Hash import SHA

def crack(digest, dictionary = "/usr/share/dict/words"):
    with open(dictionary) as dic:
        for word in dic:
            word = word.rstrip('\n')
            sha_digest = str(SHA.new(word).digest().encode("base64"))
            if sha_digest.rstrip('\n') == digest:
                return word

    return None

def crack_file(passfile):
    cracked = {}

    with open(passfile) as pass_file:
        for line in pass_file:
            user = line[:line.find(":")]
            digest = line[line.find("}") + 1:].rstrip('\n')

            if digest not in cracked:
                cracked[digest] = {}
            if user not in cracked[digest].keys():
                cracked[digest][user] = crack(digest)

    for (k, v) in cracked.iteritems():
        for (user, password) in v.iteritems():
            if password == None:
                cracked[k][user] = crack(k, "passwords-dict.txt")

    return cracked
