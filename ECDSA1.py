from lab1 import MyECDSA

class ECDSA:
    @staticmethod
    def sign_message(message):
        # Крок 1: Згенерувати випадковий приватний ключ d
        private_key, _ = MyECDSA.generate_keypair()

        # Крок 2: Обчислити публічний ключ Q як Q = d * G
        public_key = private_key.public_key()

        # Крок 3: Обчислити хеш-значення повідомлення h(m) як h(m) = SHA256(m)
        hashed_message = MyECDSA.hash_message(message.encode())  # Перетворити повідомлення в байтовий рядок

        # Крок 4: Використовувати приватний ключ d для генерації підпису (r, s) як (r, s) = ECDSA_sign(h(m), d)
        signature = MyECDSA.sign_message(private_key, hashed_message)

        # Крок 5: Повернути підпис (r, s) як кортеж
        return signature

    @staticmethod
    def hash_message(message):
        # Обчислює хеш повідомлення.
        import hashlib
        hash_object = hashlib.sha256(message)
        return hash_object.digest()

    @staticmethod
    def verify_signature(public_key, message, signature):
        # Перевіряє підпис повідомлення.
        hashed_message = ECDSA.hash_message(message)
        r, s = signature

        if r < 1 or r >= public_key.curve.order or s < 1 or s >= public_key.curve.order:
            return False

        # Обчислити `w`.
        w = MyECDSA.mod_inverse(s, public_key.curve.order)

        # Обчислити `u1`.
        u1 = (hashed_message * w) % public_key.curve.order

        # Обчислити `u2`.
        u2 = (r * w) % public_key.curve.order

        # Обчислити точку `Q`.
        Q = MyECDSA.point_addition(MyECDSA.scalar_mult(u1, public_key.curve.generator),
                           MyECDSA.scalar_mult(u2, public_key.public_numbers().y))

        # Обчислити `v`.
        v = int.from_bytes(Q, 'big') % public_key.curve.order

        # Повернути `v` дорівнює `r`.
        return v == r

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
    # Параметри еліптичної кривої
    curve = 'P-256'

    # Створіть пару ключів
    private_key, public_key = MyECDSA.generate_keypair(curve)

    # Підпис повідомлення
    signature = ECDSA.sign_message(message)

    # Перевірка повідомлення
    is_valid = ECDSA.verify_signature(public_key, message.encode(), signature)  # Convert message to bytes

    return signature, is_valid


# Ввести повідомлення
message = input("Введіть повідомлення для підпису: ")

# Підпис і перевірка повідомлення
signature, is_valid = sign_and_verify_message(message)

# Вивести отриманий підпис
print("Підпис:", signature)

if is_valid:
    print("Підпис перевірено: повідомлення дійсне.")
else:
    print("Підпис перевірено: повідомлення не дійсне")