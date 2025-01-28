import random

# Function to check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

# Modular exponentiation
def modular_exponentiation(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

# Modular inverse using extended Euclidean algorithm
def mod_inverse(a, m):
    gcd, x, _ = extended_euclidean(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist.")
    return x % m

# Extended Euclidean algorithm
def extended_euclidean(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_euclidean(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

# ElGamal encryption
def elgamal_encrypt(plaintext_number, p, e1, e2):
    r = random.randint(1, p - 1)
    c1 = modular_exponentiation(e1, r, p)
    c2 = (plaintext_number * modular_exponentiation(e2, r, p)) % p
    return c1, c2

# ElGamal decryption
def elgamal_decrypt(c1, c2, d, p):
    s = modular_exponentiation(c1, d, p)
    s_inv = mod_inverse(s, p)
    plaintext_number = (c2 * s_inv) % p
    return plaintext_number

# Main function
if __name__ == "__main__":
    try:
        # Get user input for public and private keys, and numeric plaintext
        p = int(input("Enter a large prime number (p): "))
        if not is_prime(p):
            raise ValueError("The number p must be a prime.")

        e1 = int(input("Enter the base (e1): "))
        d = int(input("Enter the private key (d): "))
        if not (1 < d < p - 1):
            raise ValueError("The private key (d) must be in the range 1 < d < p-1.")

        # Calculate e2 from e1 and d
        e2 = modular_exponentiation(e1, d, p)

        # Get numeric plaintext input (plaintext treated as a number)
        plaintext_number = int(input("Enter the numeric plaintext to encrypt: "))
        if not (0 < plaintext_number < p):
            raise ValueError("The plaintext number must be in the range 0 < plaintext < p.")

        # Encrypt the plaintext
        c1, c2 = elgamal_encrypt(plaintext_number, p, e1, e2)
        print(f"Ciphertext: (c1={c1}, c2={c2})")

        # Decrypt the ciphertext
        decrypted_number = elgamal_decrypt(c1, c2, d, p)
        print(f"Decrypted: {decrypted_number}")
    except ValueError as e:
        print(f"Error: {e}")