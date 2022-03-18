from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import argparse
from getpass import getpass 
import json
import zipfile
import struct
import pyperclip
import sys

parser = argparse.ArgumentParser(description='Cryo is a password manager for your terminal')
parser.add_argument('-a', '--add', action='store_true', help='Add a password/username combo to the database')
parser.add_argument('-g', '--get', action='store_true', help='Get a password/username combo from the database')
parser.add_argument('-d', '--dlt', action='store_true', help='Delete a password/username combo from the database')
parser.add_argument('-c', '--copy', action='store_true', help='Copy a password to the clipboard')
parser.add_argument('-l', '--list', action='store_true', help='List all password/username combos in the database')
parser.add_argument('-p', '--pswd', action='store_true', help='Set your password')

def generateKey(password):
    with open('cry.json', 'r') as f:
        data = json.load(f)
        salt = int.to_bytes(data['salt'], 16, 'big')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def checkPassword(password):
    try:
        with open("cry.pwd", 'rb') as f:
            token = f.read()
        try: 
            Fernet(password).decrypt(token)
            return True
        except:
            return False
    except:
        print("please set a password")
        print("cryo -p")
        return False
        
def setPassword():
    try:
        with open('cry.json', 'r') as f:
            print("password already set")
            # TODO allow changing password
            return
    except:
        password = getpass()
        if password != getpass("Confirm password: "):
            print("passwords do not match")
            return
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        # print(key)
        f = Fernet(key)
        token = f.encrypt(b'CHEESE')
        with open('cry.pwd', 'wb') as f:
            f.write(token)
        data = {'salt': int.from_bytes(salt, 'big')}
        with open('cry.json', 'w') as f:
            json.dump(data, f)
        print("password set")
    return

def addKey(key):
    print()
    name = input('Entry name: ')
    name = name.lower()
    username = input('Username: ')
    password = getpass("Password: ")
    if password == '':
        password = Fernet.generate_key().decode()[:32]
    elif getpass('Confirm Password: ') != password:
        print('Passwords do not match')
        exit()
    f = Fernet(key)
    content = f.encrypt(json.dumps({'username':username, 'password':password, 'name':name}).encode())
    digest = hashes.Hash(hashes.SHA256())
    digest.update(name.encode())
    name = digest.finalize().hex()[:16]
    with zipfile.ZipFile('passwords.zip', 'a') as f:
        f.writestr(name, content.decode())
    print("password added")

def getKey(password):
    name = input('Enter the entry name (case ignored): ')
    digest = hashes.Hash(hashes.SHA256())
    digest.update(name.encode())
    name = digest.finalize().hex()[:16]
    with zipfile.ZipFile('passwords.zip', 'a') as f:
        with f.open(name) as z:
            content = z.read()
    content = json.loads(Fernet(password).decrypt(content))
    print("Username: " + content['username'])
    return content['password']

def listKeys(password):
    with zipfile.ZipFile('passwords.zip', 'r') as f:
        for name in f.namelist():
            content = json.loads(Fernet(password).decrypt(f.read(name)))
            print("Entry: " + content['name'])
            print("Username: " + content['username'])
            print("Password: " + content['password'])
            print()

def delKey(password):
    name = input('Entry (case ignored): ')
    digest = hashes.Hash(hashes.SHA256())
    digest.update(name.encode())
    name = digest.finalize().hex()[:16]
    with zipfile.ZipFile('passwords.zip', 'r') as old:
        with zipfile.ZipFile('passwords2.zip', 'a') as new:
            for file in old.namelist():
                if file != name:
                    new.writestr(file, old.readfile(file))
    os.remove('passwords.zip')
    os.rename('passwords2.zip', 'passwords.zip')
    print("password deleted")

if __name__ == '__main__':
    args = parser.parse_args()
    if args.pswd:
        setPassword()
        exit()
    password = getpass()
    password = generateKey(password)
    if not checkPassword(password):
        print("Password not correct")
        exit()
    if args.add:
        addKey(password)
    elif args.get:
        password = getKey(password)
        if args.copy:
            pyperclip.copy(password)
            print("Password copied to clipboard")
            exit()
        print("Password: " + password)
    elif args.dlt:
        delKey(password)
    elif args.list:
        listKeys(password)