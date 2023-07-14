from lab1 import MyECDSA

class ECDSA:
    @staticmethod
    def sign_message(private_key, message):
        # Підписує повідомлення за допомогою приватного ключа.
        hashed_message = ECDSA.hash_message(message)
        signature = MyECDSA.sign_message(private_key, hashed_message)
        return signature

    @staticmethod
    def hash_message(message):
        # Обчислює хеш повідомлення.
        return MyECDSA.hash_message(message)

    @staticmethod
    def generate_keypair(curve='P-256'):
        # Генерує пару ключів
        return MyECDSA.generate_keypair(curve)

    @staticmethod
    def verify_signature(public_key, message, signature):
        # Перевіряє підпис повідомлення.
        hashed_message = ECDSA.hash_message(message)
        return MyECDSA.verify_signature(public_key, hashed_message, signature)

    @staticmethod
    def serialize_private_key(private_key):
        # Серіалізує приватний ключ.
        return MyECDSA.serialize_private_key(private_key)

    @staticmethod
    def deserialize_private_key(curve, serialized_private_key):
        # Десеріалізує приватний ключ.
        return MyECDSA.deserialize_private_key(curve, serialized_private_key)

    @staticmethod
    def serialize_public_key(public_key):
        # Серіалізує публічний ключ.
        return MyECDSA.serialize_public_key(public_key)

    @staticmethod
    def deserialize_public_key(curve, serialized_public_key):
        # Десеріалізує публічний ключ.
        return MyECDSA.deserialize_public_key(curve, serialized_public_key)

    @staticmethod
    def serialize_signature(signature):
        # Серіалізує підпис.
        return MyECDSA.serialize_signature(signature)

    @staticmethod
    def deserialize_signature(serialized_signature):
        # Десеріалізує підпис.
        return MyECDSA.deserialize_signature(serialized_signature)

def sign_and_verify_message(message):
    # Еліптична крива (параметри)
    curve = 'P-256'

    # Згенерувати пару ключів
    private_key, public_key = ECDSA.generate_keypair(curve)

    # Перетворити повідомлення в байтовий рядок
    message_bytes = message.encode()

    # Підписати повідомлення
    signature = ECDSA.sign_message(private_key, message_bytes)

    # Перевірити підпис
    is_valid = ECDSA.verify_signature(public_key, message_bytes, signature)

    return signature, is_valid


# Ввід повідомлення
message = input("Введіть повідомлення для підписування: ")

# Підписати повідомлення та перевірити підпис
signature, is_valid = sign_and_verify_message(message)

# Вивести отриманий підпис
print("Signature:", ECDSA.serialize_signature(signature))

if is_valid:
    print("Підпис перевірено: Повідомлення є валідним.")
else:
    print("Підпис не перевірено: Повідомлення є недійсним.")
