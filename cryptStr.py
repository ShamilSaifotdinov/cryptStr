import traceback

from base64 import urlsafe_b64encode as b64e
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from getpass import getpass

import csv
from io import StringIO

# cryptography

def _derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=salt,
        iterations=480000,
    )
    return b64e(kdf.derive(password))

def encrypt(string: str) -> bytes:
    salt = getpass("New salt: ")
    key = getpass("New key: ")

    key = _derive_key(key.encode(), salt.encode())
    return Fernet(key).encrypt(string.encode())

def decrypt(ciphertext: bytes) -> str:
    try:
        salt = getpass("Salt: ")
        key = getpass("Key: ")
        
        key = _derive_key(key.encode(), salt.encode())
        
        decMessage = Fernet(key).decrypt(ciphertext)
        return decMessage.decode()
    
    except Exception as inst:
        traceback.print_exc()

# Read/write file

def writeFile(data: bytes):
    with open("encrypted", "wb") as file:
        file.write(data)
        print("Saved!")

def openFile() ->  bytes:
    try:
        with open("encrypted", "rb") as file:
            return file.read()
    except:
        anw = input("File not found! Create new file? [y/n]: ")
        if (anw == 'y'): 
            writeFile(encrypt("login,password"))
            return openFile()
        elif (anw == 'n'):
            return
        else: openFile()

# Table

def openTable(string):
    myreader = list(csv.reader(string.splitlines()))
    return myreader

def printTable(string):
    arr = openTable(string)
    idLen = len(str(len(arr)))
    loginLen = max([len(i[0]) for i in arr])
    passwordLen = max([len(i[1]) for i in arr])
    formatStr = "{:<" + str(idLen) + "} {:<" + str(loginLen) + "} {:<" + str(passwordLen) + "}"
    for index, (login, password) in enumerate(arr):
        print (formatStr.format(index, login, password))

def addRow(string):
    login = getpass("New login: ")
    password = getpass("New password: ")
    newArr = openTable(string) + [[login, password]]
    
    with StringIO() as csvfile:
        spamwriter = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        spamwriter.writerows(newArr)
        
        writeFile(encrypt(csvfile.getvalue()))
        printTable(decrypt(openFile()))

# Main

while(True):
    cmd = input('cryptStr ')

    if (not cmd == 'exit'):
        ciphertext = openFile()

        if (ciphertext and cmd in ('open', 'add')):            
            string = decrypt(ciphertext)

            if (cmd == 'open' and ciphertext): printTable(string)
            elif (cmd == 'add' and ciphertext): addRow(string)

        else: break
    else: break