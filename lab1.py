from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from Crypto.PublicKey import ECC

class MyECDSA:
    @staticmethod
    def sign_message(private_key, message):
        hashed_message = MyECDSA.hash_message(message)
        signature = private_key.sign(hashed_message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return signature

    @staticmethod
    def hash_message(message):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        return digest.finalize()

    @staticmethod
    def generate_keypair(curve='P-256'):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def verify_signature(public_key, message, signature):
        hashed_message = MyECDSA.hash_message(message)
        try:
            public_key.verify(signature, hashed_message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return True
        except:
            return False

    @staticmethod
    def serialize_private_key(private_key):
        return private_key.to_string().hex()

    @staticmethod
    def deserialize_private_key(curve, serialized_private_key):
        return ECC.construct(curve=curve, d=int(serialized_private_key, 16))

    @staticmethod
    def serialize_public_key(public_key):
        return public_key.to_string().hex()

    @staticmethod
    def deserialize_public_key(curve, serialized_public_key):
        return ECC.import_key(serialized_public_key)

    @staticmethod
    def serialize_signature(signature):
        return signature

    @staticmethod
    def deserialize_signature(serialized_signature):
        return serialized_signature
