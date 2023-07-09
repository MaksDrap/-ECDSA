from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Вибір еліптичної кривої та параметрів
curve = ec.SECP256R1()
backend = default_backend()

# Функція гешування повідомлення
def hash_message(message):
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    digest.update(message.encode())
    return digest.finalize()

# Генерація ключової пари
def generate_key_pair():
    private_key = ec.generate_private_key(curve, backend)
    public_key = private_key.public_key()
    return private_key, public_key

# Підписання повідомлення
def sign_message(message, private_key):
    hashed_message = hash_message(message)
    signature = private_key.sign(hashed_message, ec.ECDSA(hashes.SHA256()))
    return signature

# Перевірка цифрового підпису
def verify_signature(message, signature, public_key):
    hashed_message = hash_message(message)
    try:
        public_key.verify(signature, hashed_message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

# Головна функція програми
from cryptography.exceptions import InvalidSignature

def main():
    # Генерація ключової пари
    private_key, public_key = generate_key_pair()

    while True:
        print("1. Підписати повідомлення")
        print("2. Перевірити підпис")
        print("3. Вийти")

        choice = input("Оберіть опцію: ")

        if choice == "1":
            message = input("Введіть повідомлення: ")
            signature = sign_message(message, private_key)
            print("Підпис:", signature.hex())
        elif choice == "2":
            message = input("Введіть повідомлення: ")
            signature = bytes.fromhex(input("Введіть підпис: "))
            is_valid = verify_signature(message, signature, public_key)
            if is_valid:
                print("Підпис є дійсним")
            else:
                print("Підпис недійсний")
        elif choice == "3":
            break
        else:
            print("Неправильний вибір")

if __name__ == "__main__":
    main()

