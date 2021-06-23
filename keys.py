import nacl.encoding
import nacl.signing
import nacl.utils
from nacl.exceptions import BadSignatureError

import sys
import os
sys.path.append(os.path.join(sys.path[0],'falcon_mcmc'))
from falcon_mcmc import falcon

import hashlib
import json
import pickle

from timeit import default_timer as timer


def generate_private_key(password='', salt=None, is_falcon=False):
    start = timer()
    if is_falcon:
        n, saved_polys, polys = get_polys()

        if saved_polys == False:
            private_key = falcon.SecretKey(n)
            saved_n_polys = [n, private_key.f, private_key.g, private_key.F, private_key.G]
            with open('data/polys.txt', 'wb') as f:
                pickle.dump(saved_n_polys, f)
            f.close()
            print("========================================================================================")
            print("Save the polynomials (and n) below (it will also be saved in the file /data/polys.txt):\n\n", private_key)
            print("========================================================================================")
        else:
            private_key = falcon.SecretKey(polys[0], [polys[1],  polys[2],  polys[3],  polys[4]])
    else:
        if salt == None:
            salt = os.urandom(32)
            with open('data/salt.txt', 'wb') as f:
                f.write(salt)
            f.close()
            print("=======================================================================")
            print("Save the salt below (it will also be saved in the file /data/salt.txt):\n\n", salt)
            print("=======================================================================")

        seed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, 32)

        private_key = nacl.signing.SigningKey(seed)

    end = timer()
    #print("Time elapsed for sign (ECDSA): ", end-start, "\n")

    return private_key

def generate_public_key(private_key, is_falcon=False):
    if is_falcon:
        public_key = falcon.PublicKey(private_key)
    else:
        public_key = (private_key.verify_key).encode()

    return public_key

def regen_falcon_public_key(n_in, h_in):
    public_key = falcon.PublicKey(n=n_in, h=h_in)

    return public_key

def retrieve_salt(file='data/salt.txt'):
    with open(file, 'rb') as f:
        salt = f.read()
    f.close()

    return salt

def get_polys():
    '''
    file is a pickle-generated file
    '''
    saved_polys = True
    file = None
    polys = None
    n_str = input("Enter degree of n: ")
    n = int(n_str)
    default = input("Retrieve polys from data/polys.txt? (y/n)")

    if default == 'n':
        has_polys = input("Do you have saved polys? (y/n)")

        if has_polys == 'y':
            file = input("Enter file name: ")

        elif has_polys == 'n':
            saved_polys = False

    elif default == 'y':
        file = 'data/polys.txt'

    if file != None:
        with open(file, 'rb') as f:
            polys = pickle.load(f)

    return n, saved_polys, polys

def get_salt_password():
    salt_exists = input("Do you have a salt? (y/n)")

    if salt_exists == 'y':
        default = input("Is it in /data/salt.txt? (y/n/raw)")

        if default == 'y':
            salt = retrieve_salt()

        elif default == 'n':
            file = input("Enter the name of the file: ")
            salt = retrieve_salt(file)

        elif salt_file == 'raw':
            salt = input("Enter the salt: ")

    elif salt_exists == 'n':
        salt = None

    password = input("Enter your password: ")

    return salt, password

def sign(message, private_key, ind_sym):
    '''
    message: <dict>

    ind_sym: <string> to decide if to use indendent or symmetric for FALCON
    '''
    message_bytes = json.dumps(message, sort_keys=True).encode('utf-8')

    if ind_sym == 'i':
        '''
        Default parameters to use for independent:
            - sigma_og = 70
        '''
        signature = private_key.sign(message_bytes, ind_sym, 75)
    elif ind_sym == 's':
        '''
        Default parameters to use for symmetric:
            - sigma_og = 60
            - sigma_new = 30
            - i_mix_sym = 1000
        '''
        signature = private_key.sign(message_bytes, ind_sym, 60)
    else:
        signature = private_key.sign(message_bytes)

    return signature

def verify_sign(signed_message, signature, public_key_hex, is_falcon=False):
    '''
    signed message is in bytes
    public key is in hex
    falcon public key is in <n, h> form
    '''
    public_key = bytes.fromhex(public_key_hex)
    if is_falcon:
        #convert to PublicKey object
        public_key = pickle.loads(public_key)
        public_key = falcon.PublicKey(n=public_key['n'], h=public_key['h'])
        # make sure message in bytes
        verified = public_key.verify(signed_message, signature)
    else:
        verify_key = nacl.signing.VerifyKey(public_key)

        try:
            original_message = verify_key.verify(signed_message, signature)
            verified = True
        except BadSignatureError:
            verified = False

    return verified
