def generate_key(text, key):
    key = list(key)
    if len(text) == len(key):
        return ''.join(key)
    else:
        for i in range(len(text) - len(key)):
            key.append(key[i % len(key)])
    return ''.join(key)

def vigenere_encrypt(text, key):
    encrypted = []
    for i in range(len(text)):
        char = (ord(text[i].upper()) + ord(key[i].upper()) - 2 * ord('A')) % 26
        encrypted.append(chr(char + ord('A')))
    return ''.join(encrypted)

def vigenere_decrypt(cipher, key):
    decrypted = []
    for i in range(len(cipher)):
        char = (ord(cipher[i]) - ord(key[i]) + 26) % 26
        decrypted.append(chr(char + ord('A')))
    return ''.join(decrypted)

# Example usage
if __name__ == "__main__":
    try:
        # Get user input for the text and key
        text = input("Enter the text to encrypt: ").strip()
        key = input("Enter the key: ").strip()

        # Validate inputs
        if not text.isalpha() or not key.isalpha():
            raise ValueError("Text and key must contain only alphabetic characters.")

        # Convert inputs to uppercase
        text = text.upper()
        key = key.upper()

        # Generate the key to match the length of the text
        key = generate_key(text, key)

        # Encrypt the text
        encrypted = vigenere_encrypt(text, key)
        print(f"Encrypted: {encrypted}")

        # Decrypt the text
        decrypted = vigenere_decrypt(encrypted, key)
        print(f"Decrypted: {decrypted}")
    except ValueError as e:
        print(f"Error: {e}")