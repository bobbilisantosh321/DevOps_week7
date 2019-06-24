import os
import socket
import hashlib
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from CryptoPlus.Cipher import IDEA
import time

# create session key for sending data
def getSessionKey():
    session_key = os.urandom(16)
    print("key is {0}".format(session_key))
    # encrypt CTR MODE session key
    en = AES.new(session_key, AES.MODE_CTR, counter=lambda: session_key)
    encrypto = en.encrypt(session_key)
    return encrypto

def encryptSessionPublicKey(publicKey, sessionKey):
    return publicKey.encrypt(sessionKey,16)

serverName = b'www.maryville.edu'
s = socket.socket()
print("Socket successfully created")

port = 9500

s.bind(('', port))
print("socket binded to %s" % (port))

s.listen(5)
print("socket is listening")

publicKey = b'maryville123'

while True:
    c, addr = s.accept()
    print('Got connection from', addr)
    data = c.recv(1024)
    print(data)
    request = data.decode("utf-8")
    print("Server received ", request)

    if request == 'Hello':
        c.send(serverName)
        getpbkey = c.recv(1024)
        # conversion of string to KEY
        server_public_key = RSA.importKey(getpbkey)
        # hashing the public key in server side for validating the hash from client
        hash_object = hashlib.sha1(getpbkey)
        hex_digest = hash_object.hexdigest()
        print('\n-------HEX DIGEST IS {0}---------\n'.format(hex_digest))

        if getpbkey != "":
            print("\n-----PUBLIC KEY IS {0}----- \n".format(getpbkey))
            c.send(b'YES')
            gethash = c.recv(1024)
            print("\n-----HASH OF PUBLIC KEY {0}----- \n" .format(gethash))
        if hex_digest == gethash.decode("utf-8"):
            print('Connection Established')

            # hashing sha1
            sesssionKey = getSessionKey()
            en_object = hashlib.sha1(sesssionKey)
            en_digest = en_object.hexdigest()
            print("\n-----SESSION KEY IS {0}-----\n".format(en_digest))

            data_key = encryptSessionPublicKey(server_public_key, sesssionKey)
            print("\n-----ENCRYPTED PUBLIC KEY AND SESSION KEY IS {0}-----\n".format(str(data_key)))
            c.send(str.encode(str(data_key)))
            print("\n-----HANDSHAKE COMPLETE-----")
            while True:
                # message from client
                newmess = c.recv(1024)
                decoded = newmess.decode("hex")
                # making en_digest(session_key) as the key
                key = en_digest[:16]
                print("\nENCRYPTED MESSAGE FROM CLIENT -> " + newmess)
                # decrypting message from the client
                ideaDecrypt = IDEA.new(key, IDEA.MODE_CTR, counter=lambda: key)
                dMsg = ideaDecrypt.decrypt(decoded)
                print("\n**New Message**  " + time.ctime(time.time()) + " > " + dMsg + "\n")
                mess = "\nMessage To Client -> "
                if mess != "":
                    ideaEncrypt = IDEA.new(key, IDEA.MODE_CTR, counter=lambda: key)
                    eMsg = ideaEncrypt.encrypt(mess)
                    eMsg = eMsg.encode("hex").upper()
                    if eMsg != "":
                        print("ENCRYPTED MESSAGE TO CLIENT-> " + eMsg)
                    c.send(eMsg)
        else:
            print('WRONG CONNECTION ESTABLISHED')


    c.close()

