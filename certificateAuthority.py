from Crypto import Random
from Crypto.PublicKey import RSA

publicKey = b'maryville123'
serverName = b'www.maryville.edu'

caMapper = {serverName : publicKey }
random_generator = Random.new().read
key = RSA.generate(1024, random_generator)

def getCertificate(myServer):
    if serverName == myServer:
        public = key.publickey().exportKey()
        return public
    else:
        return ""

def getKey():
    return key
