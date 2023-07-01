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
def add(username):
    password = getpass("Enter password: ")
    password1 = getpass("Repeat password: ")
    if(password == password1): 
        if not spellcheck(password): 
            return print("User add failed. Password must be at least 8 characters long and have at least one lowercase and uppercase letter and at least one number.")
        salt = base64.b64decode(start()[2:-1])
        f = open("login_podaci.txt", "a+")
        hash_username = str(base64.b64encode(SHA256.new(username.encode()+salt).digest()))
        hash_password = str(base64.b64encode(SHA256.new(password.encode()+salt).digest()))
        f.write(hash_username + " " + hash_password + "\n")
        f.close()
        return print(f"User {username} successfuly added.")
    else: return print("User add failed. Password mismatch.")
def passwd(username): 
    password = getpass("Enter new password: ")
    password1 = getpass("Repeat new password: ")
    if(password == password1):
        if not spellcheck(password): 
            return print("Password change failed. Password must be at least 8 characters long and have at least one lowercase and uppercase letter and at least one number.")
        salt = base64.b64decode(start()[2:-1])
        f = open("login_podaci.txt", "r")
        lines = f.readlines()
        f.close()
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
        return print("Password changed successfully.")
    else: return print("Password change failed. Password mismatch.")
def forcepass(username):
    salt = base64.b64decode(start()[2:-1])
    f = open("login_podaci.txt", "r")
    lines = f.readlines()
    f.close()
    new_lines = []
    for line in lines:
        l = line.rstrip().split(" ")
        if l[0] == str(base64.b64encode(SHA256.new(username.encode()+salt).digest())):
            new_lines.append(l[0] + " " + l[1] + " " + str(base64.b64encode(get_random_bytes(16))) +"\n")
        else:
            new_lines.append(line)
    f = open("login_podaci.txt", "w")
    f.writelines(new_lines)
    f.close()
    return print("User will be requested to change password on next login.")
def delete(username):
    salt = base64.b64decode(start()[2:-1])
    f = open("login_podaci.txt", "r")
    lines = f.readlines()
    f.close()
    new_lines = []
    for line in lines:
        l = line.rstrip().split(" ")
        if l[0] != str(base64.b64encode(SHA256.new(username.encode()+salt).digest())):
            new_lines.append(line)
    f = open("login_podaci.txt", "w")
    f.writelines(new_lines)
    f.close()
    return print("User successfully removed.")

if __name__ == "__main__":
    if sys.argv[1] == "add":
        if len(sys.argv) == 3: add(sys.argv[2])
        else: print("Wrong number of arguments.")
    elif sys.argv[1] == "passwd":
        if len(sys.argv) == 3:
            passwd(sys.argv[2])
        else:
            print("Wrong number of arguments.")
    elif sys.argv[1] == "forcepass":
        if len(sys.argv) == 3:
            forcepass(sys.argv[2])
        else:
            print("Wrong number of arguments.")
    elif sys.argv[1] == "del":
        if len(sys.argv) == 3:
            delete(sys.argv[2])
        else:
            print("Wrong number of arguments.")
    else:
        print("Unknown command!")
