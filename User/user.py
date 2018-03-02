import socket
import datetime
from Crypto.PublicKey import RSA



def user_pk_generation():
    secret_code = "generic_passw0rd"
    key = RSA.generate(2048)

    #generation of public/private key pair
    encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

    file_out = open("rsa_private_key.bin", "wb")
    file_out.write(encrypted_key)
    file_out = open("rsa_public_key.bin", 'wb')
    file_out.write(key.publickey().exportKey())


#user_pk_generation()

public_key = open("rsa_public_key.bin", "rb").read()


card_number = 1000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 1234))

while True:
    print(s.recv(4096).decode('utf-8'))
    bank_option = input("Choose bank option: ")
    s.send(bytes(bank_option, 'utf-8'))

    print(s.recv(4096).decode('utf-8'))
    m = input("Full name: ")
    deposited_sum = input("Deposited_sum: ")
    if m == "exit":
        s.close()
        print("Connection closed")
    package = ''.join([m, '\t', socket.gethostbyname(socket.gethostname()), '\t', str(public_key), '\t', str(deposited_sum)])
    s.send(bytes(package, 'utf-8'))

    print("Sent: ", package)
    print("REPLY From Server: " + s.recv(4096).decode('utf-8'))



'''import socket

host = 'localhost'
port = 1234
buf = 1024

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect((host, port))

print("Sending 'client1 to server\\n'")
clientsocket.send(bytes('client1\n', 'utf-8'))
print("REPLY From Server: " + clientsocket.recv(buf).decode('utf-8'))

print("Sending 'client2'")
clientsocket.send(bytes('client2', 'utf-8'))
print("REPLY From server: " + clientsocket.recv(buf).decode('utf-8'))

print("Sending 'abc'")
clientsocket.send(bytes('abc', 'utf-8'))
print("REPLY From Server: " + clientsocket.recv(buf).decode('utf-8'))

print("Sending 'abc'")
clientsocket.send(bytes('abc', 'utf-8'))
print("REPLY From Server: " + clientsocket.recv(buf).decode('utf-8'))


print("Sending 'bye'")
clientsocket.send(bytes('bye', 'utf-8'))
print("REPLY From Server: " + clientsocket.recv(buf).decode('utf-8'))

clientsocket.close()
'''