# ECDSA (Еліптична крива цифрового підпису)

Ця програма демонструє використання алгоритму цифрового підпису на основі еліптичних кривих (ECDSA).

Імпортувати модуль lab1, де знаходяться функції-обгортки:
from my_wrappers import *

Для генерації пари ключів, викличте функцію generate_keypair():
private_key, public_key = generate_keypair()

Для гешування повідомлення, викличте функцію hash_message():
hashed_message = hash_message(message)

Для підпису повідомлення приватним ключем, викличте функцію sign_message():
signature = sign_message(private_key, message)

Для перевірки цифрового підпису відкритим ключем, викличте функцію verify_signature():
valid = verify_signature(public_key, message, signature)

Для серіалізації та десеріалізації ключів та підпису, використовуйте відповідні функції:
serialized_private_key = serialize_private_key(private_key)
deserialized_private_key = deserialize_private_key(curve, serialized_private_key)

serialized_public_key = serialize_public_key(public_key)
deserialized_public_key = deserialize_public_key(curve, serialized_public_key)

serialized_signature = serialize_signature(signature)
deserialized_signature = deserialize_signature(serialized_signature)

І в кінці виведення результатів.
print("Private Key:", private_key.private_numbers().private_value)
print("Public Key:", public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
print("Hashed Message:", hashed_message)
print("Signature:", signature)
print("Valid Signature:", valid)
