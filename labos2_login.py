import base64
import os
import sys
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from getpass import getpass 

def start():
    if not(os.path.exists("login_salt.txt")):
        f = open("login_salt.txt", "w")
        salt = get_random_bytes(16)
        f.write(str(base64.b64encode(salt)))
        f.close()
        return salt
    else:
        f = open("login_salt.txt", "r")
        salt = f.readline()
        f.close()
        return salt
def spellcheck(password):
    word_split = list(password)
    lower, upper, digit = False, False, False
    if len(word_split) < 8: return False
    for letter in word_split:
        if letter.isupper(): upper = True
        elif letter.islower(): lower = True
        elif letter.isdigit(): digit = True
    if not(upper and lower and digit): return False
    return True
def login(username):
    salt = base64.b64decode(start()[2:-1])
    change = False; exists = False
    f = open("login_podaci.txt", "r")
    lines = f.readlines()
    f.close()

    for line in lines:
        l = line.rstrip().split(" ")
        if l[0] == str(base64.b64encode(SHA256.new(username.encode()+salt).digest())):
            real_password = l[1]
            exists = True
            if len(l) == 3:
                change = True

    password = getpass("Enter password: ")
    if not exists: return print("Username or password incorrect.")
    while real_password != str(base64.b64encode(SHA256.new(password.encode()+salt).digest())):
        print("Username or password incorrect.")
        password = getpass("Enter password: ")
    if change:
        password = getpass("New password: ")
        password1 = getpass("Repeat new password: ")
        while password != password1 or not spellcheck(password) or real_password ==str(base64.b64encode(SHA256.new(password1.encode()+salt).digest())):
            if not spellcheck(password): 
                print("Password change failed. Password must be at least 8 characters long and have at least one lowercase and uppercase letter and at least one number.")
            elif password != password1: 
                print("Password change failed. Password mismatch.")
            elif real_password ==str(base64.b64encode(SHA256.new(password1.encode()+salt).digest())):
                print("Password change failed. New password must be different from old password.")
            password = getpass("New password: ")
            password1 = getpass("Repeat new password: ")
        new_lines = []
        for line in lines:
            l = line.rstrip().split(" ")
            if l[0] == str(base64.b64encode(SHA256.new(username.encode()+salt).digest())):
                hash_password = str(base64.b64encode(SHA256.new(password.encode()+salt).digest()))
                new_lines.append(l[0] + " " + hash_password + "\n")
            else:
                new_lines.append(line)
        f = open("login_podaci.txt", "w")
        f.writelines(new_lines)
        f.close()
        return print("Login successful.")
    else:
        return print("Login successful.")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        login(sys.argv[1])
    else:
        print("Unknown command or wrong number of arguments!")
