from threading import Thread
import socket
import json
import random
from Crypto import Random
from Crypto.Cipher import AES
import random, string, base64
from hashlib import blake2b
from hmac import compare_digest


class MyReceivingThread(Thread):
    def __init__(self, mySocket):
        Thread.__init__(self)
        self.mySocket = mySocket

    def generate_Ks(self, keySize):
        ks = random.randrange(2 ** (keySize - 1), 2 ** keySize)
        return ks

    def encrypt(self, pk, plaintext):
        e, n = pk
        cipher = [(ord(char) ** e) % n for char in plaintext]
        # Return the array of bytes
        return cipher

    def decrypt(self, pk, ciphertext):
        # Unpack the key into its components
        d, n = pk
        # Generate the plaintext based on the ciphertext and key using a^b mod m
        plain = [chr((char ** d) % n) for char in ciphertext]
        # Return the array of bytes as a string
        return ''.join(plain)


    def decryption_aes(self,encoded_cipher_text, key, iv):
        decryption_suite = AES.new(key, AES.MODE_CBC, iv)
        plain_text = decryption_suite.decrypt(base64.b64decode(encoded_cipher_text))
        return plain_text

    def encryption_aes(self,message, key, iv):
        enc_s = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = enc_s.encrypt(message)
        encoded_cipher_text = base64.b64encode(cipher_text)
        return encoded_cipher_text

    def sign(self,msg, key):
        h = blake2b(digest_size=32, key=key)
        h.update(msg)
        sign=h.hexdigest().encode('utf-8')
        return sign

    def verify(self,msg, sign, key):
        good_sign = self.sign(msg, key)
        return compare_digest(good_sign, sign)

    def run(self):
        d = 12357
        y = {}
        ##json dosyasında public key var
        with open('data.txt') as json_file:
            g = json.load(json_file)
            private = (d, g["User2_pubKey"]["n"])
            public = (g["User2_pubKey"]["e"], g["User2_pubKey"]["n"])

        while True:
            msg = self.mySocket.recv(4000)
            received = msg.decode()  # string şeklinde dict
            messages = json.loads(received)
            encrypted_key = json.loads(messages["encrypt_key"])

            self.decrypt_key = self.decrypt(private, encrypted_key)
            messages["decrypt_key"] = self.decrypt_key  # gormek icin bunu da json dosyasına ekledim
            y.update(messages)
            json.dumps(y)

            t=messages["encrypt_key_int"]
            intKey_to_bytes = t.to_bytes((t.bit_length() + 7) // 8, 'big') or b'\0'

            iv=messages["iv"]
            iv_to_bytes = iv.to_bytes((iv.bit_length() + 7) // 8, 'big') or b'\0'

            print(messages)

            n=messages["encrypted_msg_int"]
            int_to_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\0'

            d_message=self.decryption_aes(int_to_bytes,intKey_to_bytes,iv_to_bytes)

            sign = messages["sign"]
            sign_to_bytes = sign.to_bytes((sign.bit_length() + 7) // 8, 'big') or b'\0'
            verify=self.verify(d_message,sign_to_bytes,intKey_to_bytes)
            if(verify == True ):
                print("message: ",d_message.decode(), ("/verified/"))

            ### send nonce u aldığı gibi  gondermesi icin
            f = {}
            f["nonce"] = messages["nonce"]
            s = json.dumps(f)
            self.mySocket.send(bytes(s, 'utf-8'))


            ###


    """
def handshake(d,k):
    if(d["nonce"]==k["nonce"]):
        print("authentication saglandi")
    else: print("authentication saglanamadi")
    """


class MySendingThread(Thread):
    def __init__(self, mySocket):
        Thread.__init__(self)
        self.mySocket = mySocket

    def nonce(self, keySize):
        nonce = random.randrange(2 ** (keySize - 1), 2 ** keySize)
        return nonce

    def encrypt(self, pk, plaintext):
        e, n = pk
        cipher = [(ord(char) ** e) % n for char in plaintext]
        # Return the array of bytes
        return str(cipher)

    def decrypt(self, pk, ciphertext):
        # Unpack the key into its components
        d, n = pk
        # Generate the plaintext based on the ciphertext and key using a^b mod m
        plain = [chr((char ** d) % n) for char in ciphertext]
        # Return the array of bytes as a string
        return ''.join(plain)

    def run(self):
        self.k = {}

        while True:
            data = input()
            self.k['data'] = data
            # print(type(myReceiveThread.messages["encrypt_key"]))
            self.k["decrypt_key"]=myReceiveThread.decrypt_key
            s = json.dumps(self.k)
            self.mySocket.send(bytes(s, 'utf-8'))



# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# send a connection request
s.connect(('127.0.0.1', 4000))
# create a thread to send data => User2
mySendThread = MySendingThread(s)
# create a thread to receive data from User2
myReceiveThread = MyReceivingThread(s)
mySendThread.start()
myReceiveThread.start()
