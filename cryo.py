from re import A
from tabnanny import check
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
    # with open('cry.json', 'r') as f:
    #     data = json.load(f)
    #     salt = int.to_bytes(data['salt'], 16, 'big')
    with zipfile.ZipFile('passwords.zip', 'r') as f:
        with f.open('cry.json', 'r') as s:
            content = json.loads(s.read())
            salt = int.to_bytes(content['salt'], 16, 'big')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def generateName(name, password, filename='passwords.zip'):
    with zipfile.ZipFile(filename, 'r') as f:
        token = f.read('cry.pwd')
    digest = hashes.Hash(hashes.SHA256())
    digest.update(name.encode() + Fernet(password).decrypt(token))
    return digest.finalize().hex()[:16]

def checkPassword(password):
    try:
        with zipfile.ZipFile('passwords.zip', 'r') as f:
            token = f.read('cry.pwd')
        try: 
            Fernet(password).decrypt(token)
            return True
        except:
            return False
    except:
        print("please set a password")
        print("cryo -p")
        return False


def savePassword(password, filename='passwords.zip'):
    print("Saving password")
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    secure_message = os.urandom(32)
    with zipfile.ZipFile(filename, 'a') as f:
        with f.open('cry.pwd', 'w') as c:
            c.write(Fernet(key).encrypt(secure_message))
        with f.open('cry.json', 'w') as c:
            c.write(json.dumps({'salt': int.from_bytes(salt, 'big')}).encode())
    return key

def changePassword():
    for i in range(3):
        old_pass = getpass("Current Password: ")
        if checkPassword(generateKey(old_pass)):
           break 
        print("incorrect password")
    else:
        print("too many incorrect passwords")
        return
    while True:
        new_pass = getpass("New Password: ")
        if new_pass == getpass("Confirm Password: "):
            break
        print("passwords do not match")
    new_key = savePassword(new_pass, filename='passwords2.zip')
    old_key = generateKey(old_pass)
    with zipfile.ZipFile('passwords.zip', 'r') as old:
        with zipfile.ZipFile('passwords2.zip', 'a') as new:
            for name in old.namelist():
                if name.endswith('.pwd') or name.endswith('.json'):
                    continue
                with old.open(name) as f:
                    content = f.read()
                data = json.loads(Fernet(old_key).decrypt(content))
                new.writestr(generateName(data['name'], new_key, 'passwords2.zip'), 
                    Fernet(new_key).encrypt(json.dumps(data).encode()))
    os.remove('passwords.zip')
    os.rename('passwords2.zip', 'passwords.zip')
    print("password changed")

    
def setPassword():
    if os.path.exists('passwords.zip'):
        changePassword()
        return
    
    while True:
        password = getpass()
        if password == getpass("Confirm password: "):
            break
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
    secure_message = os.urandom(32)
    token = f.encrypt(secure_message)
    with zipfile.ZipFile('passwords.zip', 'a') as f:
        f.writestr('cry.pwd', token)
        data = {'salt': int.from_bytes(salt, 'big')}
        f.writestr('cry.json', json.dumps(data))
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
    f = Fernet(key)
    content = f.encrypt(json.dumps({'username':username, 'password':password, 'name':name}).encode())
    name = generateName(name, key)
    with zipfile.ZipFile('passwords.zip', 'a') as f:
        if name in f.namelist():
            print("name already exists")
            overwrite = input("Overwrite? (y/n) ")
            if overwrite.lower != 'y':
                print("Cancelling entry")
                return
        f.writestr(name, content.decode())
    print("password added")

def getKey(password):
    print()
    name = input('Entry: ')
    name = generateName(name, password)
    with zipfile.ZipFile('passwords.zip', 'a') as f:
        with f.open(name) as z:
            content = z.read()
    content = json.loads(Fernet(password).decrypt(content))
    print()
    print("Username: " + content['username'])
    return content['password']

def listKeys(password):
    with zipfile.ZipFile('passwords.zip', 'r') as f:
        for name in f.namelist():
            if name.endswith('.json') or name.endswith('.pwd'):
                continue
            content = json.loads(Fernet(password).decrypt(f.read(name)))
            print()
            print("Entry: " + content['name'])
            print("Username: " + content['username'])
            print("Password: " + content['password'])

def delKey(password):
    name = input('Entry (case ignored): ')
    name = generateName(name, password)
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
    if not os.path.exists('passwords.zip'):
        print("Please set a password")
        setPassword()
        exit()
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
    else:
        parser.print_help()