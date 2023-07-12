from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from Crypto.PublicKey import ECC

def sign_message(private_key, message):
    # Підписання повідомлення
    hashed_message = hash_message(message)
    signature = private_key.sign(hashed_message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return signature

def hash_message(message):
    # Гешування повідомлення
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    return digest.finalize()

def generate_keypair(curve='P-256'):
    # Генерація пари ключів
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key
def verify_signature(public_key, message, signature):
    # Перевірка цифрового підпису
    hashed_message = hash_message(message)
    try:
        public_key.verify(signature, hashed_message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except:
        return False

def serialize_private_key(private_key):
    # Серіалізація особистого ключа
    return private_key.to_string().hex()

def deserialize_private_key(curve, serialized_private_key):
    # Десеріалізація особистого ключа
    return ECC.construct(curve=curve, d=int(serialized_private_key, 16))

def serialize_public_key(public_key):
    # Серіалізація відкритого ключа
    return public_key.to_string().hex()

def deserialize_public_key(curve, serialized_public_key):
    # Десеріалізація відкритого ключа
    return ECC.import_key(serialized_public_key)

def serialize_signature(signature):
    # Серіалізація цифрового підпису
    return signature

def deserialize_signature(serialized_signature):
    # Десеріалізація цифрового підпису
    return serialized_signature
