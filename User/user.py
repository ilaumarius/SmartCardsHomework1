import socket
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
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
        print(verify_sign("temp.bin", ks, received_c))


def generate_new_hash_chain(chain_length):
    hash_base = get_random_bytes(16)
    initial_hash = SHA256.new(hash_base).digest()
    for index in range(chain_length-1):
        hasher = SHA256.new(initial_hash).digest()
        print(hasher)
        initial_hash = hasher
    return hasher

def pay():
    pass
#bank_register()
#generate_new_hash_chain(4)

