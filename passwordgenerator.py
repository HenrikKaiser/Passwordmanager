import math
import os.path
import os
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import string


def help(sender):
    match sender:
        case "main":
            print("Use 'save password' to generate a password or save a password.\n"
                  "Use 'Load Password' to load an already saved password.\n")
        case "save password already exists":
            print("It looks there is already a password file for this use.\n"
                  "You can delete this password file or choose a different use!")
        case "save":
            print("Specify the use of your password as well as a masterpassword,\nwhich will be used to encrypt and decrypt your password.")
        case "load":
            print("To access your passwords, you will need the Use,\n "
                  "as well as the master password for the use (Saved in 'use'masterpassword.txt")

    
def save_password(unencrypted, key, use, masterpw):
    keystring = ""
    i: int = 0
    while i < 26:
        keystring += key[i]
        i += 1
    if (os.path.isfile(f"{use}key.bin")) and (os.path.isfile(f"{use}pw.bin")) and (os.path.isfile(f"{use}enckey.bin")):
        while True:
            print("This file already exists!\n1: delete the file\n2: choose another file\n/help for help\n/b go back")
            choice = input("Your choice: ")
            match choice:
                case "1":
                    os.remove(f"{use}key.bin")
                    os.remove(f"{use}pw.bin")
                    os.remove(f"{use}enckey.bin")
                    os.remove(f"{use}masterpw.txt")
                    print("Successfully deleted the File!")
                    break
                case "2":
                    save()
                case "/b":
                    main()
                case "/help":
                    help(sender="save password already exists")
                case _:
                    print("Please enter a valid choice or use /help for help")
                    save()
    else:
        simple_key = get_random_bytes(32)
        with open(f"{use}masterpw.txt", "w") as f:
            f.write(masterpw)
            f.close()
        with open(f"{use}pw.bin", "wb") as f:
            enckey = PBKDF2(masterpw, simple_key, dkLen=32)
            cipherpw = AES.new(enckey, AES.MODE_CBC)
            bytepw = unencrypted.encode('utf-8')
            ciper_data = cipherpw.encrypt(pad(bytepw, AES.block_size))
            f.write(cipherpw.iv)
            f.write(ciper_data)
            f.close()
        with open(f"{use}key.bin", "wb") as f:
            cipherkey = AES.new(enckey, AES.MODE_CBC)
            bytekey = keystring.encode('utf-8')
            cipher_data = cipherkey.encrypt(pad(bytekey, AES.block_size))
            f.write(cipherkey.iv)
            f.write(cipher_data)
            f.close()
        with open(f"{use}enckey.bin", "wb") as f:
            f.write(simple_key)
            f.close()
        main()


def encrypt(unencrypted, key, use, masterpw):
    i = 0
    pw = ""
    while i < len(unencrypted):
        if unencrypted[i].isalpha():
            asciivalue = ord(unencrypted[i])
            if unencrypted[i].islower():
                pw = pw + key[asciivalue - 97].lower()
            else:
                pw = pw + key[asciivalue - 65].upper()
        else:
            pw = pw + unencrypted[i]
        i += 1
    print(f"Your password is: {pw}")
    save_password(unencrypted, key, use, masterpw)
    return pw


def generate_password(length, use, masterpw):
    chars = string.ascii_letters + string.digits + string.punctuation
    pw = ""
    while len(pw) < length:
        pw = pw + random.choice(chars)
    key = string.ascii_uppercase
    print(f"Your password is {pw}")
    save_password(pw, key, use, masterpw)


def decrypt(use, password):
    temp = 0
    if (os.path.isfile(f"{use}key.bin")) and (os.path.isfile(f"{use}pw.bin")) and (os.path.isfile(f"{use}enckey.bin")):
        with open(f"{use}masterpw.txt", "r") as f:
            master = f.read()
            if not (master == password):
                print("Wrong master password!")
                load()
            f.close()
        with open(f"{use}enckey.bin", "rb") as f:
            simple_key = f.read()
            f.close()
        with open(f"{use}key.bin", "rb") as f:
            iv = f.read(16)
            decrypt_data = f.read()
            enckeykey = PBKDF2(password, simple_key, dkLen=32)
            f.close()
        cipherkey = AES.new(enckeykey, AES.MODE_CBC, iv=iv)
        try:
            temp = unpad(cipherkey.decrypt(decrypt_data), AES.block_size)
            temp = temp.decode("utf-8")
        except ValueError:
            print("Your master password is wrong!")
            load()
        with open(f"{use}pw.bin", "rb") as f:
            iv2 = f.read(16)
            decrypt_data2 = f.read()
            f.close()
        enckeypw = PBKDF2(password, simple_key, dkLen=32)
        cipherpw = AES.new(enckeypw, AES.MODE_CBC, iv=iv2)
        try:
            unencrypted = unpad(cipherpw.decrypt(decrypt_data2), AES.block_size)
            unencrypted = unencrypted.decode("utf-8")
        except ValueError:
            print("Your master password is wrong!")
            load()
            return 1
        key = {}
        i = 0
        while i < len(temp):
            key[i] = temp[i]
            i += 1
        pw = ""
        i = 0
        while i < len(unencrypted):
            if unencrypted[i].isalpha():
                asciivalue = ord(unencrypted[i])
                if unencrypted[i].islower():
                    pw = pw + key[asciivalue - 97].lower()
                else:
                    pw = pw + key[asciivalue - 65].upper()
            else:
                pw = pw + unencrypted[i]
            i += 1
        print(f"Your password is {pw}")
        print("")
        main()
    else:
        print("Enter an existing use or create a new password file!")
        load()


def save():
    print("Do you want to choose a password or generate one?\n1: choose\n2: generate\n/help for help\n/b: back")
    choice = input("Enter your choice: ")
    match choice:
        case "1":
            choice: str = input("Do you want to encrypt your password? (y/n) ").lower()
            use = input("Enter your use: ")
            masterpw = input("Choose a master password: ")
            password = input("Enter your password: ")
            match choice:
                case "y":
                    tempkey = input("Enter your key: ")
                    key = {}
                    i = 0
                    while i < 26:
                        if i < len(tempkey):
                            key[i] = tempkey[i]
                        else:
                            temp = i - len(tempkey) * math.floor(i / len(tempkey))
                            key[i] = tempkey[temp]
                        i += 1
                    encryptedpw = encrypt(password, key, use, masterpw)
                    print(f"Your encrypted password is {encryptedpw}")
                    main()
                case "n":
                    key = string.ascii_lowercase
                    save_password(password, key, use, masterpw)
                case _:
                    print("Enter a valid choice!")
                    save()
        case "2":
            use = input("Enter your use: ")
            masterpw = input("Choose a master password: ")
            length = 0
            try:
                length = int(input("Enter your length: "))
            except ValueError:
                print("Enter a valid integer")
                save()
            generate_password(length, use, masterpw)
        case "/help":
            help(sender=save)
        case "/b":
            main()
        case _:
            print("Enter a valid choice!")
            save()


def load():
    use = input("Enter your use: ")
    password = input("Enter your master password: ")
    decrypt(use, password)


def main():
    while True:
        print("What do you want do do?\n1: Save password\n2: Load password\n3: Exit\n/help for help")
        do = input("Enter your choice: ")
        match do:
            case "1":
                save()
            case "2":
                load()
            case "3":
                exit()
            case "/help":
                help(sender="main")
            case _:
                print("Enter a number between 1 and 2!")



main()