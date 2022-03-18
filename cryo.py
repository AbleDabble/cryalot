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

parser = argparse.ArgumentParser(description='Cryo is a password manager for your terminal')
parser.add_argument('-a', '--add', action='store_true', help='Add a password/username combo to the database')
parser.add_argument('-g', '--get', action='store_true', help='Get a password/username combo from the database')
parser.add_argument('-d', '--dlt', action='store_true', help='Delete a password/username combo from the database')
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
    print("Enter the entry name (case ignored) this will be used to lookup the password later")
    name = input('Entry name: ')
    username = input('Username: ')
    password = getpass("Password (leave blank to auto-generate password: ")
    if password == '':
        password = Fernet.generate_key().decode()
    elif getpass('Confirm Password: ') != password:
        print('Passwords do not match')
        exit()
    f = Fernet(key)
    content = f.encrypt(json.dumps({'username':username, 'password':password}).encode())
    with zipfile.ZipFile('passwords.zip', 'w') as f:
        f.writestr(name, content.decode())
    print("password added")

def getKey(password):
    name = input('Enter the entry name (case ignored): ')
    with zipfile.ZipFile('passwords.zip', 'a') as f:
        with f.open(name) as z:
            content = z.read()
    content = json.loads(Fernet(password).decrypt(content))
    print("Username: " + content['username'])
    print("Password: " + content['password'])

def listKeys(password):
    with zipfile.ZipFile('passwords.zip', 'r') as f:
        for name in f.namelist():
            content = json.loads(Fernet(password).decrypt(f.read(name)))
            print("Entry: " + name)
            print("Username: " + content['username'])
            print("Password: " + content['password'])
            print()
        
if __name__ == '__main__':
    args = parser.parse_args()
    if args.pswd:
        setPassword()
        exit()
    password = getpass()
    password = generateKey(password)
    if not checkPassword(password):
        print("password not correct")
        exit()
    if args.add:
        addKey(password)
    elif args.get:
        getKey(password)
    elif args.dlt:
        delKey(password)
    elif args.list:
        listKeys(password)