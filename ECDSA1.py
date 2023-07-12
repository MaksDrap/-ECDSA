from lab1 import generate_keypair, hash_message, sign_message, verify_signature
from cryptography.hazmat.primitives import serialization


# Генерація пари ключів
private_key, public_key = generate_keypair(curve='P-256')

# Повідомлення для підпису
message = "Hello, world!"

# Гешування повідомлення
hashed_message = hash_message(message)

# Підписання повідомлення
signature = sign_message(private_key, message)

# Перевірка цифрового підпису
valid = verify_signature(public_key, message, signature)

# Виведення результатів
print("Private Key:", private_key.private_numbers().private_value)
print("Public Key:", public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
print("Hashed Message:", hashed_message)
print("Signature:", signature)
print("Valid Signature:", valid)
