import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def hash_token(token, salt):
    '''
    Calculates the hash of a token and salt.
    input is unhexlified

    token and salt must contain an even number of hex digits or
    a binascii.Error exception will be raised
    '''
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(binascii.unhexlify(token))
    digest.update(binascii.unhexlify(salt))
    return binascii.hexlify(digest.finalize()).decode()