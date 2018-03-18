from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
import threading as thread
import sys
import datetime
import random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64

host = '127.0.0.1'
port = 1250
buf = 1024

addr = (host, port)

serversocket = socket(AF_INET, SOCK_STREAM)
serversocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serversocket.bind(addr)
serversocket.listen(10)

clients = [serversocket]


def verify_sign(public_key_loc, signature, data):
    pub_key = open(public_key_loc, "r").read()
    #print("FUNCTION DATA: ", data)
    #print("FUNCTION SIGNATURE: ", signature)
    rsakey = RSA.importKey(pub_key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()

    digest.update(bytes(data, 'utf-8'))

    ds = RSA.tobytes(signature)
    #print("FROM FUNC digest: ", digest.digest())
    #print("FROM FUNC signature: ", ds)
    #print("FROM FUNC signature len: ", len(ds))

    kk = signer.verify(digest, ds)
    if signer.verify(digest, ds):
        return True
    return False


def handler(clientsocket, clientaddr):
    print("Accepted connection from: ", clientaddr)
    m = input("Vendor name: ")
    clientsocket.send(bytes(m, 'utf-8'))
    while True:
        clientsocket.send(bytes("Send 1 for payment. Send 'exit' to quit.", 'utf-8'))
        menu_option = clientsocket.recv(4096).decode('utf-8')
        print("Menu option: ", menu_option)
        if menu_option == "exit" or not menu_option:
            print("Closing connection")
            clientsocket.send(bytes("Closing connection\n", 'utf-8'))
            break

        elif menu_option[0] == '1':
            file_lines = str()
            with open("product_list.txt", "r") as f:
                for x in f.readlines():
                    file_lines += x
            clientsocket.send(bytes(file_lines, 'utf-8'))
            clientsocket.send(bytes("Send product number.", 'utf-8'))
            product_number = clientsocket.recv(4096).decode('utf-8')
            #print(product_number)
            first_val = clientsocket.recv(4096).decode('utf-8')
            print(first_val)
            if first_val == "first_time":
                complete_package = clientsocket.recv(4096).decode('utf-8')
                print(type(complete_package))
                print("Complete package: ", complete_package, len(complete_package))
                print(complete_package.split('\t'))
                data = complete_package.split('\t')[1:7]
                signature = complete_package.split('\t')[7:]
                conc_data = str()
                conc_sign = str()
                for item in data:
                    conc_data += item + '\t'
                for item in signature:
                    conc_sign += item + '\t'
                conc_sign = conc_sign[:-1]
                #conc_data = conc_data[:-1]
                print("conc_sign: ", conc_sign, len(conc_sign))

                #print(type(data))
                print("sig:", signature, len(signature))
                user_sign_check = verify_sign("../User/rsa_user_public_key.bin", conc_sign, conc_data)
                print(user_sign_check)
                print(complete_package.split('\t'))
                other_sig = str()
                print(complete_package.split('\t'))
                for item in complete_package.split('\t')[1:2]:
                    other_sig += item + '\t'
                other_sig = other_sig[:-1]
                print(other_sig)
                data_from_bank = open("../User/message.bin").read()
                bank_sign_check = verify_sign("../Bank/rsa_bank_public_key.bin", other_sig, data_from_bank)
                print(bank_sign_check)
                with open("commits.bin", "ab") as c:
                    k = bytes(conc_data, 'utf-8') + b'\n'
                    c.write(k)

                if user_sign_check and bank_sign_check:
                    clientsocket.send(bytes("Signatures passed.", 'utf-8'))

            print("Payment")
            payment_response = clientsocket.recv(4096).decode('utf-8')
            print(payment_response)

            user_name = clientsocket.recv(4096).decode('utf-8')
            print(user_name)

            payment_package = clientsocket.recv(4096).decode('utf-8')
            print(payment_package)

            payment_hash = payment_package.split('....')[0]
            payment_nr_of_hashes = payment_package.split('....')[1]
            print("Payment hash: ", payment_hash)

            with open("commits.bin", "rb") as f:
                file_lines = f.read()
                for item in file_lines.split(b'\t\n')[:-1]:
                    hashs_base = item.split(b'\t')[2:-3][0].decode('utf-8')
                    name = item.split(b'\t')[-1].decode('utf-8')
                    print(hashs_base, len(hashs_base))
                    print(name)
                    if name == user_name:
                        hasher = str()
                        print("HASH base: ", hashs_base)
                        print("PAY hash : ", payment_hash)
                        initial_hash = RSA.tobytes(payment_hash)
                        for index in range(int(payment_nr_of_hashes)):
                            hasher = SHA256.new(initial_hash).digest()
                            print("hasher ind: ", RSA.tostr(hasher))
                            # print(hasher)
                            initial_hash = hasher
                        print("HASH base: ", hashs_base)
                        print("Hasher f : ", RSA.tostr(hasher))
                        if RSA.tostr(hasher) == hashs_base:
                            print("VALID hashes => valid payment")
            

            #clientsocket.send(bytes("Send X cash.", 'utf-8'))
            '''
            package_list = str(product_number).split('\t')
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

            bank_package = ''.join([full_name, '\t', ip_adress, '\t', bank_public_key, '\t', str(deposited_sum),
                                    '\t', str(expiry_date), '\t', str(card_number), '\t'])

            with open("lightweight_database.txt", "r") as f:
                file_lines = [x for x in f.readlines()]
            print("FILE:!!!", file_lines)
            with open("lightweight_database.txt", "a") as f:
                if len(file_lines) == 0:
                    f.write(bank_package + '\n')
                    #clientsocket.send(bytes("BANK: authentication completed!" + '\n', 'utf-8'))
                else:
                    for item in file_lines:
                        if str(card_number) not in item and full_name not in item:
                            #clientsocket.send(bytes("BANK: authentication completed!" + '\n', 'utf-8'))
                            f.write(bank_package + '\n')
                            break
                        #else:
                            #clientsocket.send(bytes("BANK: authentication failed!" + '\n', 'utf-8'))


            hash = SHA256.new(RSA.tobytes(bank_package))

            #print("data: ", bank_package)
            #print("hashed package: ", hash.digest())
            #print("len hashed package: ", len(hash.digest()))


            bank_private_key = RSA.import_key(open('rsa_bank_private_key.bin').read(), "some_passw0rd")
            cipher_rsa = PKCS1_v1_5.new(bank_private_key)

            bank_signed_package = cipher_rsa.sign(hash)
            #print("LENGTH: ", len(bank_signed_package))

            #print("LENGTH rsastr: ", len(RSA.tostr(bank_signed_package)))

            bank_signed_package = RSA.tostr(bank_signed_package)

            t1 = base64.b64encode(bank_package.encode())
            t2 = base64.b64encode(bank_signed_package.encode())

            complete_package = bank_package.join(['\t', bank_signed_package])

           # print("data: ", bank_package)
            #print("signature: ", bank_signed_package)
            #print("len signature: ", len(bank_signed_package))
            #print("complete package: ", complete_package)

            clientsocket.send(RSA.tobytes(complete_package))'''



        else:
            clientsocket.send(bytes("ECHO: " + menu_option + '\n', 'utf-8'))

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
