import socket
import time
import hashlib
from CryptoPlus.Cipher import IDEA

import certificateAuthority
import threading

def send(t,message,key):
    mess = message + " : "
    key = key[:16]
    whole = message + " : " + mess
    ideaEncrypt = IDEA.new(key, IDEA.MODE_CTR, counter=lambda: key)
    eMsg = ideaEncrypt.encrypt(whole)
    eMsg = eMsg.encode("hex").upper()
    if eMsg != "":
        print("ENCRYPTED MESSAGE SENT TO SERVER-> " + eMsg)
    s.send(eMsg)

def recv(t,key):
    newmess = s.recv(1024)
    print("\nENCRYPTED MESSAGE RECEIVED FROM SERVER-> " + newmess)
    key = key[:16]
    decoded = newmess.decode("hex")
    ideaDecrypt = IDEA.new(key, IDEA.MODE_CTR, counter=lambda: key)
    dMsg = ideaDecrypt.decrypt(decoded)
    print("\n New Message From Server  " + time.ctime(time.time()) + " : " + dMsg + "\n")

s = socket.socket()

port = 9500

s.connect(('127.0.0.1', port))

s.send(b'Hello')
serverName = s.recv(1024)
print("ServerName Received {0}".format(serverName))
publicKey = certificateAuthority.getCertificate(serverName)


print("Client sent Hello")
s.send(publicKey)
print("Client Received ")
status = s.recv(1024)
print(status)
hash_object = hashlib.sha1(publicKey)
hex_digest = hash_object.hexdigest()
if status == b'YES':
    s.send(str.encode(hex_digest))

    #Connection session key
    data_key = s.recv(1024)
    print("Received {0}".format(data_key))
    encrypted_key = eval(data_key.decode("utf-8"))
    decrypt = certificateAuthority.getKey().decrypt(encrypted_key)
    # hashing sha1
    en_object = hashlib.sha1(decrypt)
    en_digest = en_object.hexdigest()
    print ("\n-----ENCRYPTED PUBLIC KEY AND SESSION KEY FROM SERVER-----")
    print (data_key)
    print ("\n-----DECRYPTED SESSION KEY-----")
    print (en_digest)
    print ("\n-----HANDSHAKE COMPLETE-----\n")
    alais = "\nServer Client Https Secured Connection check -> "

    while True:
        thread_send = threading.Thread(target=send, args=("------Sending Message------", alais, en_digest))
        thread_recv = threading.Thread(target=recv, args=("------Recieving Message------", en_digest))
        thread_send.start()
        thread_recv.start()

        thread_send.join()
        thread_recv.join()
        time.sleep(0.5)
    time.sleep(60)
    server.close()
else:
    print("\n-----CONNECTION_NOT_ESTABLISHED-----\n")


s.close()





