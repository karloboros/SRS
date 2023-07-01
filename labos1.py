import sys
import base64
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES

def toString(byte_array):
    binary_string = ''.join(format(byte, '08b') for byte in (byte_array))
    return binary_string
def toBytes(binary_string):
    byte_array = bytearray(int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8))
    return byte_array

def init(master_password):
    f = open("podaci.txt", "w+")
    open("sifre.txt", "w")

    salt = get_random_bytes(16)
    f.write(str(base64.b64encode(salt)))  
    f.write('\n')
    hash = SHA256.new(master_password.encode()+salt)
    f.write(str(base64.b64encode(hash.digest())))
    f.close()
    print("Password manager initialized.")
    #f = open("podaci.txt", "r+")
    #print(f.readlines())

def put(master_password, domain, password):
    f = open("podaci.txt", "r")
    linije = f.readlines()
    
    if (str(base64.b64encode(SHA256.new(master_password.encode()+base64.b64decode(linije[0][2:-1])).digest()))[2:-1] != linije[1][2:-1]):
        print("Master password incorrect or integrity check failed.")
        return 0
    f.close()

    salt = get_random_bytes(16)
    key = scrypt(master_password.encode(), salt, 16, N=2**14, r=8, p=1)
    
    cipher = AES.new(key, AES.MODE_EAX)
    cipher.update(salt)    
    ciphertextDom, tagDom = cipher.encrypt_and_digest(domain.encode())
    nonceDom = cipher.nonce   

    temp = password
    cipher = AES.new(key, AES.MODE_EAX)
    cipher.update(salt)    
    ciphertextPass, tagPass = cipher.encrypt_and_digest(password.encode())
    noncePass = cipher.nonce   

    sifre = open("sifre.txt", "r")
    linije = sifre.readlines()
    sifre.close()
    # domena sifra salt nonceD nonceP tagD tagS
    new = True
    tekst = ""
    for red in linije:
        podaci = red.strip().split(" ")
        key = scrypt(master_password.encode(), (toBytes(podaci[2])), 16, N=2**14, r=8, p=1 )
        cipher = AES.new(key, AES.MODE_EAX, nonce=(toBytes(podaci[3])))
        cipher.update(toBytes(podaci[2])) 
        plaintextDom = cipher.decrypt(toBytes(podaci[0]))
        if plaintextDom.decode() == domain:
            new = False
            tekst += toString(ciphertextDom) + " " + toString(ciphertextPass) + " " + toString(salt) + " " + toString(nonceDom) + " " + toString(noncePass) + " " + toString(tagDom) + " " + toString(tagPass) + "\n"
        else:
            tekst += red
    
    if new:
        tekst += toString(ciphertextDom) + " " + toString(ciphertextPass) + " " + toString(salt) + " " + toString(nonceDom) + " " + toString(noncePass) + " " + toString(tagDom) + " " + toString(tagPass) + "\n"
    sifre = open("sifre.txt", "w")
    sifre.write(tekst)
    sifre.close()
    print(f"Stored password for {domain}!")

def get(master_password, domain):
    f = open("podaci.txt", "r")
    linije = f.readlines()
    
    if (str(base64.b64encode(SHA256.new(master_password.encode()+base64.b64decode(linije[0][2:-1])).digest()))[2:-1] != linije[1][2:-1]):
        print("Master password incorrect or integrity check failed.")
        return 0
    f.close()

    f = open("sifre.txt", "r")
    linije = f.readlines()
    f.close()

    found = False
    for red in linije:
        podaci = red.strip().split(" ")
        key = scrypt(master_password.encode(), toBytes(podaci[2]), 16, N=2**14, r=8, p=1 )
        cipher = AES.new(key, AES.MODE_EAX, nonce=(toBytes(podaci[3])))
        cipher.update(toBytes(podaci[2])) 
        plaintextDom = cipher.decrypt(toBytes(podaci[0]))
        try:
            cipher.verify(toBytes(podaci[5]))
            if plaintextDom.decode() == domain:
                key = scrypt(master_password.encode(), (toBytes(podaci[2])), 16, N=2**14, r=8, p=1 )
                cipher = AES.new(key, AES.MODE_EAX, nonce=(toBytes(podaci[4])))
                cipher.update(toBytes(podaci[2])) 
                plaintextPass = cipher.decrypt(toBytes(podaci[1]))
                cipher.verify(toBytes(podaci[6]))
                found = True
                print(f"Password for {domain} is: {plaintextPass.decode()}")
        except:
            continue
    if not found:
        print("Master password incorrect or integrity check failed.") 

if __name__ == "__main__":
    if sys.argv[1] == "init":
        init(sys.argv[2])
    elif sys.argv[1] == "put":
        if len(sys.argv) == 5:
            put(sys.argv[2], sys.argv[3], sys.argv[4])
        else:
            print("You need to enter the master password, domain and password.")
    elif sys.argv[1] == "get":
        if len(sys.argv) == 4:
            get(sys.argv[2], sys.argv[3])
        else:
            print("You need to enter the master password and domain.")
    else:
        print("Unknown command!")
