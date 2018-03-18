import socket
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import datetime
import base64



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


def user_pk_generation():
    secret_code = "generic_passw0rd"
    key = RSA.generate(1024)

    encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

    file_out = open("rsa_user_private_key.bin", "wb")
    file_out.write(encrypted_key)
    file_out = open("rsa_user_public_key.bin", 'wb')
    file_out.write(key.publickey().exportKey())


#user_pk_generation()

public_key = open("rsa_user_public_key.bin", "rb").read()


def bank_register():
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

        #print(s.recv(4096).decode('utf-8'))
        received_certif = RSA.tostr(s.recv(4096)) #.decode('utf-8')

        initial = received_certif
        #print("FULL CERTIF: ", received_certif)
        bank_public_key = str(received_certif).split('\t')[3].replace('b\'', '', 1)
        bank_public_key = bank_public_key.replace('\'', '', 11)
        received_signature = received_certif.split('\t')[7]
        ks = str()
        for item in received_certif.split('\t')[7:]:
            ks += item
            ks += '\t'
            #print("ITEM: ", item)
        ks = ks[:-1]

        received_c = str(str(received_certif).split(received_signature)[0])[1:]
        #print("certif: ", received_c)
        hash = SHA256.new()
        hash.update(bytes(received_c, 'utf-8'))
        hashed_package = hash.digest()
        #print("hashed package: ", hashed_package)
        file_out = open("temp.bin", "w+")

        k = len(bank_public_key.split('\\n'))
        c = 0
        for item in bank_public_key.split('\\n'):
            c += 1
            if c != k:
                file_out.write(item + '\n')
            else:
                file_out.write(item)
        file_out.close()


        #print("data: ", received_c)
        #print("signature: ", received_signature)
        #k1 = base64.b64encode(received_c.encode())
        #k2 = base64.b64encode(received_signature.encode())
        #print("encoded data: ", k1)
        #print("encoded signature: ", k2)

        #print("KKKKK: ", len(ks), ks)
        #print("KKKKK: ", len(received_signature), received_signature)
        open("signature.bin", "wb").write(RSA.tobytes(ks))
        open("message.bin", "wb").write(RSA.tobytes(received_c))
        print(verify_sign("temp.bin", ks, received_c))


def generate_new_hash_chain(chain_length):
    hash_base = get_random_bytes(16)
    initial_hash = SHA256.new(hash_base).digest()
    hash_chain_list = []
    hash_chain_list.append(initial_hash)
    for index in range(chain_length-1):
        hasher = SHA256.new(initial_hash).digest()
        #print(hasher)
        hash_chain_list.append(hasher)
        initial_hash = hasher
    hash_str = RSA.tostr(hasher)
    if hash_str.find('\t') != -1:
        generate_new_hash_chain(chain_length)
    print("HASH LIST: ", hash_chain_list)
    return hash_chain_list


def pay():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 1250))

    while True:
        user_name = input("Enter username: ")
        vendor_name = s.recv(4096).decode('utf-8')
        print(vendor_name)
        check = False
        with open("vendors_list.txt", "r") as f:
            file_lines = [x for x in f.readlines()]
            for item in file_lines:
                if vendor_name == item[:-1]:
                    check = True
                    break
        f.close()

        menu_option = s.recv(4096).decode('utf-8')
        print(menu_option)
        menu_sent = input("choose option: ")
        s.send(bytes(menu_sent, 'utf-8'))
        product_list = s.recv(4096).decode('utf-8')
        print(product_list)
        print(s.recv(4096).decode('utf-8'))
        product_number = input("Choose product number: ")
        s.send(bytes(product_number, 'utf-8'))

        with open("hashes.bin", "rb") as f:
            file_lines = [x[:-1] for x in f.readlines()]
        if len(file_lines) == 0:
            chain_length = input("Choose chain length:")
            hash_chain = generate_new_hash_chain(int(chain_length))
        else:
            hash_chain = file_lines

        if not check:
            s.send(bytes("first_time", 'utf-8'))
            sig = RSA.tostr(open("signature.bin", "rb").read())
            chain_length = input("Choose chain length:")
            hash_chain = generate_new_hash_chain(int(chain_length))
            with open("hashes.bin", "wb") as f:
                for item in hash_chain:
                    f.write(item)
                    f.write(b'\n')
            chain_base = RSA.tostr(hash_chain[-1])
            print("HASH CHAIN: ", hash_chain)
            actual_date = (datetime.date.today()).isoformat()

            commit = ''.join(
                    [sig, '\t', str(actual_date),'\t', chain_base,  '\t', str(chain_length), '\t', vendor_name, '\t', user_name, '\t'])
            user_private_key = RSA.import_key(open('rsa_user_private_key.bin').read(), "generic_passw0rd")
            cipher_rsa = PKCS1_v1_5.new(user_private_key)
            print("HEREEEE")
            print(commit, len(commit))
            hash = SHA256.new()
            hash.update(bytes(commit, 'utf-8'))
            signed_commit = RSA.tostr(cipher_rsa.sign(hash))

            complete_package = commit.join(['\t', signed_commit])
            print("signed_commit:", signed_commit, len(signed_commit))
            print(type(complete_package))
            print("Complete package: ", complete_package, len(complete_package))
            #product_number = input("Choose product number: ")
            s.send(bytes(complete_package, 'utf-8'))
            check = s.recv(4096).decode('utf-8')
            print(check)
            if check == "Signatures passed.":
                with open("vendors_list.txt", "a") as f:
                    f.write(vendor_name + '\n')

        s.send(bytes("not_first_time", 'utf-8'))
        product_number = int(product_number)
        payment_nr = int(product_list.split('\n')[product_number-1].split(' ')[1][:-1])
        payment_packet = "".join([RSA.tostr(hash_chain[-payment_nr-1]), '....', str(payment_nr)])
        print("Payment package: ", payment_packet)

        s.send(bytes(user_name, 'utf-8'))
        s.send(bytes(payment_packet, 'utf-8'))



        #print(s.recv(4096).decode('utf-8'))
        #m = input("Full name: ")
        #deposited_sum = input("Deposited_sum: ")
        #if m == "exit":
        #    s.close()
        #    print("Connection closed")
        #package = ''.join(
        #    [m, '\t', socket.gethostbyname(socket.gethostname()), '\t', str(public_key), '\t', str(deposited_sum)])
        #s.send(bytes(package, 'utf-8'))

        ''''# print(s.recv(4096).decode('utf-8'))
        received_certif = RSA.tostr(s.recv(4096))  # .decode('utf-8')

        initial = received_certif
        # print("FULL CERTIF: ", received_certif)
        bank_public_key = str(received_certif).split('\t')[3].replace('b\'', '', 1)
        bank_public_key = bank_public_key.replace('\'', '', 11)
        received_signature = received_certif.split('\t')[7]
        ks = str()
        for item in received_certif.split('\t')[7:]:
            ks += item
            ks += '\t'
            # print("ITEM: ", item)
        ks = ks[:-1]

        received_c = str(str(received_certif).split(received_signature)[0])[1:]
        # print("certif: ", received_c)
        hash = SHA256.new()
        hash.update(bytes(received_c, 'utf-8'))
        hashed_package = hash.digest()
        # print("hashed package: ", hashed_package)
        file_out = open("temp.bin", "w+")

        k = len(bank_public_key.split('\\n'))
        c = 0
        for item in bank_public_key.split('\\n'):
            c += 1
            if c != k:
                file_out.write(item + '\n')
            else:
                file_out.write(item)
        file_out.close()

        # print("data: ", received_c)
        # print("signature: ", received_signature)
        # k1 = base64.b64encode(received_c.encode())
        # k2 = base64.b64encode(received_signature.encode())
        # print("encoded data: ", k1)
        # print("encoded signature: ", k2)

        # print("KKKKK: ", len(ks), ks)
        # print("KKKKK: ", len(received_signature), received_signature)
        print(verify_sign("temp.bin", ks, received_c))'''
pay()
#bank_register()
#generate_new_hash_chain(4)

