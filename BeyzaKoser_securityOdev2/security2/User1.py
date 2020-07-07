from threading import Thread
import socket
import json
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random, string, base64
from hashlib import blake2b


class SendingThread(Thread):

    def __init__(self, mySocket):
        Thread.__init__(self)
        self.mySocket = mySocket


    def encrypt(self, pk, plaintext):
        e, n = pk
        cipher = [(ord(char) ** e) % n for char in plaintext]
        return str(cipher)

    def decrypt(self, pk, ciphertext):
        d, n = pk
        plain = [chr((char ** d) % n) for char in ciphertext]
        return ''.join(plain)

    def nonce(self, keySize):
        nonce = random.randrange(2 ** (keySize - 1), 2 ** keySize)
        return nonce

    def generate_Ks(self, keySize):
        ks = random.randrange(2 ** (keySize - 1), 2 ** keySize)
        return ks

    def sign(self,msg, key):
        h = blake2b(digest_size=32, key=key)
        h.update(msg)
        sign=h.hexdigest().encode('utf-8')
        return sign

    def verify(self,msg,key):
        good_sign = self.sign(msg, key)
        return good_sign


    def encryption_aes(self,message, key, iv):
        enc_s = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = enc_s.encrypt(message)
        encoded_cipher_text = base64.b64encode(cipher_text)
        return encoded_cipher_text

    def decryption_aes(self,encoded_cipher_text, key, iv):
        decryption_suite = AES.new(key, AES.MODE_CBC, iv)
        plain_text = decryption_suite.decrypt(base64.b64decode(encoded_cipher_text))
        return plain_text


    def run(self):
        self.d = {}
        symmetric_key=get_random_bytes(16) #yeni key
        y_to_int = int.from_bytes(symmetric_key, "big")
        iv = Random.new().read(AES.block_size)
        with open('data.txt') as json_file:
            data = json.load(json_file)
            sys1_pubKey=(data["User2_pubKey"]["e"],data["User2_pubKey"]["n"])

        encrypt_key = self.encrypt(sys1_pubKey, str(symmetric_key))#key paylasimi icin


        while True:
            data = input()

            l = list(data)
            c = len(l)
            while c < 16:
                l.append(" ")
                data = "".join(l)
                c = len(l)

            data_byte=str.encode(data)
            message=self.encryption_aes(data_byte,symmetric_key,iv)
            sign = int.from_bytes(self.sign(data_byte,symmetric_key), "big")

            self.d['data'] = data
            self.d['encrypted_message'] = str(message)
            self.d['publicKey'] = sys1_pubKey
            self.d["nonce"] = self.nonce(16)
            self.d["encrypt_key"] = encrypt_key
            self.d["encrypt_key_int"] = y_to_int
            self.d["iv"] = int.from_bytes(iv, "big") #iv yi int olarak yolladım
            self.d["sign"]=sign

            byte_to_int = int.from_bytes(message, "big")
            self.d["encrypted_msg_int"]=byte_to_int
            s = json.dumps(self.d)
            self.mySocket.send(bytes(s, 'utf-8'))
            print("uretilen nonce : ", self.d["nonce"])


class ReceivingThread(Thread):
    def __init__(self, mySocket):
        Thread.__init__(self)
        self.mySocket = mySocket

    def run(self):
        # write code to receive data continuously
        d=21461
        while True:
            self.msg = self.mySocket.recv(4000)
            self.received = self.msg.decode()  # string şeklinde dict
            self.receiveMessage = json.loads(self.received)
            #print(self.receiveMessage)
            print("gelen nonce : ",self.receiveMessage["nonce"])
            handshake(sendThread.d,self.receiveMessage)
            break


def handshake(d, k):
    h = {}
    if (d["nonce"] == k["nonce"]):
        print("authentication saglandi")
        y={"ack":"acknowledgement message"}
        d.update(y)
        s = json.dumps(d)
        sendThread.mySocket.send(bytes(s, 'utf-8'))

    else:
        print("authentication saglanamadi")
        h["ack"]="authentication failed"
        s = json.dumps(h)
        sendThread.mySocket.send(bytes(s, 'utf-8'))

# create a socket object
s = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)
s.bind(('127.0.0.1', 4000))
s.listen()
# accept the incoming connection request
mySocket, address = s.accept()
# create a thread to send data
sendThread = SendingThread(mySocket)
# create an another to receive data
receiveThread = ReceivingThread(mySocket)
# start both threads
sendThread.start()
receiveThread.start()


