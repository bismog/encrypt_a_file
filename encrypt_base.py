
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64decode,b64encode

plain_file = '/biubiu/plain_file'
decrypt_file = '/biubiu/decrypt_file'
encrypt_file = '/biubiu/encrypt_file'
prikey = '/biubiu/id_rsa'
pubkey = '/biubiu/id_rsa.pub'
# The default chunk size for files. The current value is equivalent to 16 kb.
CHUNK_SIZE = 2**14

def enc_file(infile, outfile):
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    # public_key = key.publickey()
    bin_pubkey =  key.publickey().exportKey('DER')
    pubkey_obj =  RSA.importKey(bin_pubkey)

    with open(prikey, 'wb') as f:
        f.write(key.exportKey('PEM').decode('ascii'))
        f.close()

    with open(pubkey, 'wb') as f:
        f.write(key.publickey().exportKey('PEM').decode('ascii'))
        f.close()

    # Generate random passphrase
    # passphrase = os.urandom(16)
    passphrase = 'xxxxxxxxxxxxxxxx'         ## should be multiple of 16B, 32B or more

    # Encrypt random passphrase
    cipher = Cipher_PKCS1_v1_5.new(pubkey_obj)
    cipher_pass = cipher.encrypt(passphrase.encode('utf-8'))
    print(cipher_pass)

    iv = '\x00' * 16
    aes = AES.new(passphrase, AES.MODE_CBC, iv)
    # with open(infile, 'rb+') as f:
    #     with open(outfile, 'wb+') as of:
    #         for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
    #             of.write(aes.encrypt(chunk))
    with open(infile, 'rb') as f:
        with open(outfile, 'wb') as of:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                of.write(aes.encrypt(chunk))

def dec_file(infile, outfile):

    passphrase = 'xxxxxxxxxxxxxxxx'
    iv = '\x00' * 16
    aes = AES.new(passphrase, AES.MODE_CBC, iv)
    # with open(infile, 'rb+') as f:
    #     with open(outfile, 'wb+') as of:
    #         for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
    #             of.write(aes.encrypt(chunk))
    with open(infile, 'rb') as f:
        with open(outfile, 'wb') as of:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                of.write(aes.decrypt(chunk))


def main():
    enc_file(plain_file, encrypt_file)
    dec_file(encrypt_file, decrypt_file)
    with open(decrypt_file, 'r') as f:
        print(f.readlines())

if __name__ == "__main__":
    main()




