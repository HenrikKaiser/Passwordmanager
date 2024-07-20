import linecache
import os
import hashlib
import string
import math

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random


class PASSWORDFILE:
    def __init__(self, passwordfile, masterpassword):
        self.passwordfile = passwordfile if passwordfile.endswith('/') else passwordfile + '/'
        self.masterpassword = masterpassword
        self.masterpath = f"{self.passwordfile}masterpw.bin"
        self.keypath = f"{self.passwordfile}key.txt"
        self.passwordpath = f"{self.passwordfile}pw.bin"
        self.simplepath = f"{self.passwordfile}simple.bin"
        self.enckeypath = f"{self.passwordfile}enckey.bin"
        self.usepath = f"{self.passwordfile}use.txt"
        self.fileexists = False

    def create_passwordfile(self):
        os.makedirs(self.passwordfile, exist_ok=True)

        if not (os.path.isfile(self.enckeypath)) and not (os.path.isfile(self.passwordpath)) and not (os.path.isfile(self.simplepath)) and not(os.path.isfile(self.keypath)):
            with open(self.masterpath, "w") as f:
                f.write(self.masterpassword)

            self.fileexists = False
            open(self.enckeypath, "wb").close()
            open(self.passwordpath, "wb").close()
            open(self.keypath, "w").close()
            open(self.usepath, "w").close()
            open(self.simplepath, "wb").close()
        else:
            print("This password file already exists!")
            self.fileexists = True

    def load_masterpassword(self):
        if not os.path.isfile(self.masterpath):
            return False
        with open(self.masterpath, "r") as f:
            loadedpw = f.read()
            if self.masterpassword != loadedpw:
                print("Wrong master password!")
                return False
        return True

    def get_pos(self, location, use, target="None"):
        bytesuse = use.encode("utf-8")
        nextuse = ""
        with open(self.usepath, "r") as f:
            for line in f:
                if use in line:
                    nextuse = f.readline()
            f.close()
        with open(location, "rb") as f:
            content = f.read()  # Get the content of the file
            f.close()

        enceyuse = use.encode("utf-8")
        index = content.find(enceyuse) + len(enceyuse)  # get the index of where the use is
        if index == -1:
            return None

        enceynextuse = nextuse.strip("\n").encode("utf-8")
        indexnextuse = content.find(enceynextuse)

        match target:
            case "None":
                if nextuse == "":
                    return content[index:len(content)]
                else:
                    return content[index: indexnextuse]
            case "iv":
                if nextuse == "":
                    return content[index:index + 16]
                else:
                    return content[index: index + 16]
            case "data":
                if nextuse == "":
                    return content[index + 16: len(content)]
                else:
                    return content[index + 16: indexnextuse]

    def generate_password(self, use, length):
        #Generate a password with custom length
        chars = string.ascii_letters + string.digits + string.punctuation
        pw = ''.join(random.choice(chars) for _ in range(length))
        keys = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        pws = self.save_password(use, pw)
        self.save_key(use, keys, pws)
        return pws

    def save_key(self, uses, keys, password):
        keys = (keys * (math.ceil(26 / len(keys))))[:26]
        #save the key

        with open(self.keypath, "a") as f:
            f.write(uses + "\n")
            f.write(keys + "\n")
            f.close()
        #Unencrypt
        unencrypted = self.encrypt_password(password, keys)
        return unencrypted

    def load_key(self, uses, passwords):
        with open(self.usepath, "r") as f:
            for line in f:
                if uses in line:
                    nextuse = f.readline()
            f.close()

        with open(self.keypath, "r") as f:
            content = f.read()

        index = content.find(uses) + len(uses)

        #Get the key
        if nextuse == "":
            unencrypted = content[index:len(content)].strip("\n")
        else:
            indexnextuse = content.find(nextuse) + len(uses)
            unencrypted = content[index: indexnextuse].strip("\n")

        unencrypted = self.encrypt_password(passwords, unencrypted)
        return unencrypted

    def encrypt_password(self, passwords, keys):
        encpws = ""
        for char in passwords:
            if char.isalpha():
                ascii_val = ord(char)
                if char.islower():
                    encpws += keys[(ascii_val - 97)].lower()
                else:
                    encpws += keys[(ascii_val - 65)].upper()
            else:
                encpws += char
        return encpws

    def save_password(self, uses, passwords):
        #Check if use already exists
        with open(self.usepath, "r+") as f:
            for line in f:
                if uses in line:
                    print("This use already exists")
                    return False
            f.write(f"{uses}\n")
            f.close()

        #generate and save simplekey
        simplekey = get_random_bytes(32)
        bytesuse = uses.encode("utf-8")
        with open(self.simplepath, "ab") as f:
            f.write(bytesuse + simplekey)
            f.close()

        #generate and save salt
        salt = PBKDF2(self.masterpassword, simplekey, dkLen=32)
        with open(self.enckeypath, "ab") as f:
            f.write(bytesuse + salt)
            f.close()

        #generate and save data and cipher
        cipher = AES.new(salt, AES.MODE_CBC)
        bytepw = passwords.encode("utf-8")
        data = cipher.encrypt(pad(bytepw, AES.block_size))
        with open(self.passwordpath, "ab") as f:
            f.write(bytesuse + cipher.iv + data)
            f.close()

        #return the password
        return passwords

    def load_password(self, uses):
        #load the simplekey
        simplekey = self.get_pos(self.simplepath, uses)
        if simplekey is None:
            print("Please enter a valid use!")
            return None

        #Get the iv and data
        iv = self.get_pos(self.passwordpath, uses, target="iv")
        data = self.get_pos(self.passwordpath, uses, target="data")
        if iv is None or data is None:
            print("Please enter a valid use!")
            return None

        #Get the salt
        salt = self.get_pos(self.enckeypath, uses)

        #Get cipher
        cipher = AES.new(salt, AES.MODE_CBC, iv)

        #unencrypt the password
        try:
            unencrypted = unpad(cipher.decrypt(data), AES.block_size). decode("utf-8")
        except:
            print("Your master password is wrong or the data is corrupted!")
            return None

        #return the password
        return unencrypted

def main():
    while True:
        print("What do you want to do?\n1: Create password file\n2: Save password\n3: Generate a password\n4: Load a password")
        choice = input("Enter your choice: ")
        match choice:
            case "1":
                print("Choose a name for the passwordfile as well as a masterpassword")
                name = input("Name: ")
                masterpassword = input("Masterpassword: ")
                passwordfiles = PASSWORDFILE(name, masterpassword)
                passwordfiles.create_passwordfile()
            case "2":
                encrypt = input("Do you want to encrypt your password? (y/n)")
                if encrypt == "y":
                    name = input("Name of your passwordfile: ")
                    masterpassword = input("Masterpassword: ")
                    passwordfiles = PASSWORDFILE(name, masterpassword)
                    mpw = passwordfiles.load_masterpassword()
                    if mpw:
                        use = input("Choose a use: ")
                        key = input("Choose a key: ")
                        password = input("Choose a password: ")
                        pw = passwordfiles.save_password(use, password)
                        epw = passwordfiles.save_key(use, key, password)
                        if pw is False:
                            continue
                        else:
                            if pw is not None:
                                print(f"Your password is {epw}!")
                            else:
                                continue
                    else:
                        print("Your masterpassword is wrong!")
                        continue
                elif encrypt == "n":
                    name = input("Name of your passwordfile: ")
                    masterpassword = input("Masterpassword: ")
                    passwordfiles = PASSWORDFILE(name, masterpassword)
                    mpw = passwordfiles.load_masterpassword()
                    if mpw:
                        use = input("Choose a use: ")
                        key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        password = input("Choose a password: ")
                        pw = passwordfiles.save_password(use, password)
                        epw = passwordfiles.save_key(use, key, password)
                        if pw is False:
                            continue
                        else:
                            if pw is not None:
                                print(f"Your password is {epw}!")
                            else:
                                continue
                    else:
                        print("Your masterpassword is wrong!")
                        continue
                else:
                    print("Enter a valid choice!")
                    continue
            case "3":
                name = input("Name of your passwordfile: ")
                masterpassword = input("Masterpassword: ")
                passwordfiles = PASSWORDFILE(name, masterpassword)
                mpw = passwordfiles.load_masterpassword()
                if mpw:
                    use = input("Choose a use: ")
                    try:
                        length = int(input("Choose a length: "))
                    except:
                        print("Please enter a number!")
                        continue
                    pw = passwordfiles.generate_password(use, length)
                    key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    pw = passwordfiles.save_password(use, pw)
                    epw = passwordfiles.save_key(use, key, pw)
                    if pw is False:
                        continue
                    else:
                        if pw is not None:
                            print(f"Your password is {epw}!")
                        else:
                            continue
                else:
                    print("Your masterpassword is wrong! ")
                    continue
            case "4":
                name = input("Name of your passwordfile: ")
                masterpassword = input("Masterpassword: ")
                passwordfiles = PASSWORDFILE(name, masterpassword)
                mpw = passwordfiles.load_masterpassword()
                if mpw:
                    use = input("Enter your use: ")
                    pw = passwordfiles.load_password(use)
                    if pw is False:
                        continue
                    else:
                        if pw is not None:
                            pws = passwordfiles.load_key(use, pw)
                            print(f"Your password is {pws}")
                        else:
                            continue
            case _:
                print("Enter a valid choice!")
                continue

if __name__ == "__main__":
    main()

