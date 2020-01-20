#I use this module because I don't really know cryptography beyond the basics
#this helps me use cryptography in other projects without thinking much about it
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
def encrypt(key,info):
    encoded=info.encode()
    f=Fernet(key.encode())
    encrypted=f.encrypt(encoded)
    ret=encrypted.decode()
    return ret
def decrypt(key,info):
    f=Fernet(key.encode())
    decrypted=f.decrypt(info.encode())
    message=decrypted.decode()
    return message
def random_key():
    key=Fernet.generate_key()
    return key.decode()
def key_from_password(provided):
    password_provided=provided.encode()
    salt=b'p^\xe9\x92\xd6:q\xaa\xb6\xfc/\xc4]A\xd9q'
    kdf=PBKDF2HMAC(algorithm=hashes.SHA3_256(),length=32,salt=salt,iteration=1000,backend=default_backend())
    key=base64.urlsafe_b64decode(kdf.derive(password_provided))
    return key.decode()
print(random_key())
