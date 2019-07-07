
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Util import Counter
from base64 import b64decode,b64encode

import os
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

plain_file = 'plain_file'
decrypt_file = 'decrypt_file'
encrypt_file = 'encrypt_file'
prikey = 'id_rsa'
pubkey = 'id_rsa.pub'
# The default chunk size for files. The current value is equivalent to 16 kb.
CHUNK_SIZE = 2**14
PASS_LEN = 3 * 1024

def enc_pass(passphrase, en_len):
    '''
    Generate random passphrase, then encrypt with random public key(asymmetric 
    algorithm RSA).
    '''
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    bin_pubkey =  key.publickey().exportKey('DER')
    pubkey_obj =  RSA.importKey(bin_pubkey)

    with open(prikey, 'wb') as f:
        f.write(key.exportKey('PEM').decode('utf-8'))
        f.close()

    with open(pubkey, 'wb') as f:
        f.write(key.publickey().exportKey('PEM').decode('utf-8'))
        f.close()

    # Encrypt random passphrase
    cipher = Cipher_PKCS1_v1_5.new(pubkey_obj)
    cipher_pass = cipher.encrypt(passphrase)

    # suffix space if less than en_len
    if len(cipher_pass) < en_len:
        cipher_pass += ' ' * (en_len - len(cipher_pass))

    return cipher_pass

def dec_pass(cipher_pass):
    '''
    Decrypt passphrase with RSA private key.
    '''
    print('length of cipher pass is %d' % len(cipher_pass))
    prikey_obj = RSA.importKey(open(prikey, "rb"))
    cipher = Cipher_PKCS1_v1_5.new(prikey_obj)
    plain_pass = cipher.decrypt(cipher_pass, None)
    print('\"' + plain_pass + '\"')
    return plain_pass

def enc_file(infile, outfile, passphrase):
    '''
    Encrypt plain text file with passphrase.
    AES256, mode CBC, fixed IV.
    '''

    iv = '\x00' * 16
    aes = AES.new(passphrase, AES.MODE_CBC, iv)
    with open(infile, 'rb') as f:
        with open(outfile, 'wb') as of:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                of.write(aes.encrypt(chunk))

def suffix_pass(file, passphrase):
    '''
    Suffix fixed length passphrase(encrypted) to encrypted file context.
    '''
    with open(file, 'ab') as of:
        of.write(passphrase)

def truncate_pass(file, en_len):
    '''
    Remove suffixed passphrase from encrypted file context.
    '''
    f_len = os.path.getsize(file)
    if f_len <= en_len:
        logger.error('Insufficient file length')
        return -1;
    with open(file, 'rb+') as f:
        f.seek(f_len - en_len, os.SEEK_SET)
        f.truncate()

def get_pass(file, en_len):
    '''
    Get suffixed passphrase(encrypted) from the end of file context.
    '''
    f_len = os.path.getsize(file)
    if f_len <= en_len:
        logger.error('Insufficient file length')
        return -1;
    with open(file, 'rb') as f:
        f.seek(f_len - en_len, os.SEEK_SET)
        cipher = f.read(en_len)

    # The last one or more character of passphrase may also be space, 
    # simply strip them may truncate real elements. So fix them up 
    # to be multiple of 16.
    stripped = cipher.strip()
    if len(stripped) % 16 != 0:
        stripped = ' ' * (16 - len(stripped) % 16)
    
    return stripped

def dec_file(infile, outfile, passphrase):
    '''
    Decrypt file by using decrypted passphrase.
    ''' 

    iv = '\x00' * 16
    aes = AES.new(passphrase, AES.MODE_CBC, iv)
    with open(infile, 'rb') as f:
        with open(outfile, 'wb') as of:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                of.write(aes.decrypt(chunk))


def main():
    # Generate random passphrase
    passphrase = os.urandom(16)
    print('raw password that I generate: \"%s\"' % passphrase)

    # Encyrpt file
    enc_file(plain_file, encrypt_file, passphrase)
    p =  enc_pass(passphrase, PASS_LEN)
    suffix_pass(encrypt_file, p)

    # Decrypt file
    p = get_pass(encrypt_file, PASS_LEN)    
    truncate_pass(encrypt_file, PASS_LEN)
    dp = dec_pass(p)
    dec_file(encrypt_file, decrypt_file, dp)
    with open(decrypt_file, 'r') as f:
        print(f.readlines())

if __name__ == "__main__":
    main()




