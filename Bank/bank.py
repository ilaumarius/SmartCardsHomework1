from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
import time
import threading as thread
import sys
import datetime
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import hashlib
import base64
import base64

host = '127.0.0.1'
port = 1234
buf = 1024

addr = (host, port)

serversocket = socket(AF_INET, SOCK_STREAM)
serversocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serversocket.bind(addr)
serversocket.listen(10)

clients = [serversocket]


def bank_pk_generation():
    secret_code = "some_passw0rd"
    key = RSA.generate(1024)

    #generation of public/private key pair
    encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

    file_out = open("rsa_bank_private_key.bin", "wb")
    file_out.write(encrypted_key)
    file_out = open("rsa_bank_public_key.bin", 'wb')
    file_out.write(key.publickey().exportKey())

#bank_pk_generation()


def handler(clientsocket, clientaddr):
    print("Accepted connection from: ", clientaddr)
    while True:
        clientsocket.send(bytes("Send 1 for registration. Send 'exit' to quit.", 'utf-8'))
        data = clientsocket.recv(4096).decode('utf-8')
        print(data)
        if data == "exit" or not data:
            print("Closing connection")
            clientsocket.send(bytes("Closing connection\n", 'utf-8'))
            break

        elif data[0] == '1':
            clientsocket.send(bytes("Send full name and sum to be deposited.", 'utf-8'))
            data_package = clientsocket.recv(4096).decode('utf-8')
            package_list = str(data_package).split('\t')
            #print(package_list)
            full_name = package_list[0]
            ip_adress = package_list[1]
            client_public_key = package_list[2].replace('b\'', '', 1)
            client_public_key = client_public_key.replace('\'', '', 1)
            deposited_sum = package_list[3]
            card_number = random.randint(1000, 9999)
            bank_public_key = open("rsa_bank_public_key.bin", "rb").read()
            bank_public_key = str(bank_public_key).replace('b\'', '', 1)
            bank_public_key = bank_public_key.replace('\'', '', 1)
            expiry_date = (datetime.date.today() + datetime.timedelta(365 / 12)).isoformat()
            # des_session_key = get_random_bytes(8)
            # print("Clasic key: ", des_session_key)
            # print("Str key:", des_session_key)
            bank_package = ''.join([full_name, '\t', ip_adress, '\t', bank_public_key, '\t', str(deposited_sum),
                                    '\t', str(expiry_date), '\t', str(card_number), '\t'])

            hash = SHA256.new(RSA.tobytes(bank_package))
            #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!CHECK THAT HASH
            #hash.update(bytes(bank_package, 'utf-8'))
            #hash.update(base64.b64encode(bytes(bank_package, 'utf-8')))
            #hash.update(base64.b64encode(bank_package))
            print("data: ", bank_package)
            print("hashed package: ", hash.digest())
            print("len hashed package: ", len(hash.digest()))

            #cipher_des = DES.new(des_session_key, DES.MODE_OFB)
            #ciphertext = cipher_des.iv + cipher_des.encrypt(RSA.tobytes(bank_signed_package))
            #print("DES: ", ciphertext)

            bank_private_key = RSA.import_key(open('rsa_bank_private_key.bin').read(), "some_passw0rd")
            cipher_rsa = PKCS1_v1_5.new(bank_private_key)

            bank_signed_package = cipher_rsa.sign(hash)
            print("LENGTH: ", len(bank_signed_package))
            #print(len(bank_package))
            #print("Bank signed: ", bank_signed_package)
            print("LENGTH rsastr: ", len(RSA.tostr(bank_signed_package)))

            bank_signed_package = RSA.tostr(bank_signed_package)
            #bank_signed_package = str(bank_signed_package).replace('b\'', '', 1)
            #bank_signed_package = bank_signed_package[:-1]
            #print("LENGTH srt: ", len(bank_signed_package))

            #print("Bank signed: ", bank_signed_package)
            #print("Bank signed: ", base64.b64encode(bank_signed_package.encode()))
            t1 = base64.b64encode(bank_package.encode())
            t2 = base64.b64encode(bank_signed_package.encode())
            #print("data: ", bank_package)
            #print("signature: ", bank_signed_package)
            #print("t1: ", t1)
            #print("t2: ", t2)
            complete_package = bank_package.join(['\t', bank_signed_package])
            #complete_package = t1 + base64.b64encode('\t'.encode()) + t2
            #print(len(bank_signed_package))
            #print(len(complete_package))

            print("data: ", bank_package)
            print("signature: ", bank_signed_package)
            print("len signature: ", len(bank_signed_package))
            print("complete package: ", complete_package)

            #clientsocket.send(bytes(complete_package, 'utf-8'))
            #print(base64.b64encode(complete_package))
            clientsocket.send(RSA.tobytes(complete_package))



        else:
            clientsocket.send(bytes("ECHO: " + data + '\n', 'utf-8'))

    clients.remove(clientsocket)
    clientsocket.close()

'''
def push():
    while True:
        for i in clients:
            if i is not serversocket:
                i.send(bytes("Curent date and time: " + str(datetime.datetime.now()) + '\n', 'utf-8'))
        time.sleep(10)

thread._start_new_thread(push, ())
'''

while True:
    try:
        print("Server is listening for connections\n")
        clientsocket, clientaddr = serversocket.accept()
        clients.append(clientsocket)
        thread._start_new_thread(handler, (clientsocket, clientaddr))
    except:
        print("Closing server socket...")
        serversocket.close()
        sys.exit(20)
