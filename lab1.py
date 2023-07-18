from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from Crypto.PublicKey import ECC
import random
import math
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

    @staticmethod
    def random_scalar(n):
        while True:
            k = random.randint(1, n - 1)
            if math.gcd(k, n) == 1:
                return k

    @staticmethod
    def scalar_mult(k, point):
        # Convert the raw byte string to an elliptic curve point
        P = ec.EllipticCurvePublicNumbers.from_encoded_point(point, ec.SECP256R1()).public_key()

        # Get the curve parameters
        curve = ec.SECP256R1()
        p = curve.p

        # Perform scalar multiplication k * P
        Q = P.public_numbers().curve.generator * k

        # Encode the resulting point Q as a raw byte string and return
        Q_encoded = Q.public_numbers().encode_point()
        return Q_encoded

    @staticmethod
    def point_addition(point1, point2):
        # Convert the raw byte strings to elliptic curve points
        P = ec.EllipticCurvePublicNumbers.from_encoded_point(point1, ec.SECP256R1()).public_key()
        Q = ec.EllipticCurvePublicNumbers.from_encoded_point(point2, ec.SECP256R1()).public_key()

        # Get the curve parameters
        curve = ec.SECP256R1()
        a = curve.a
        p = curve.p

        if P == Q:
            # If P and Q are equal, perform a doubling operation
            s = (3 * P.x * P.x + a) * pow(2 * P.y, -1, p)
        else:
            # If P and Q are distinct, calculate the slope s as (Q_y - P_y) / (Q_x - P_x)
            s = (Q.y - P.y) * pow(Q.x - P.x, -1, p)

        # Calculate the new point R
        R_x = (s * s - P.x - Q.x) % p
        R_y = (s * (P.x - R_x) - P.y) % p

        # Encode the new point as a raw byte string and return
        R_encoded = ec.EllipticCurvePublicNumbers(R_x, R_y, curve).encode_point()
        return R_encoded

    @staticmethod
    def mod_inverse(a, m):
        """Calculate the modular inverse of a modulo m."""
        if math.gcd(a, m) != 1:
            raise ValueError("The inverse does not exist.")
        return pow(a, -1, m)