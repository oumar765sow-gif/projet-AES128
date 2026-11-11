
from aes import encrypt_block, decrypt_block

print("Demarrage du test AES-128...")

# Cle de chiffrement de 128 bits
key = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
)

# Bloc de texte clair de 128 bits
plaintext = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
)

# Resultat attendu selon le vecteur de test AES-128
expected = "69c4e0d86a7b0430d8cdb78070b4c55a"

# Chiffrement
ciphertext = encrypt_block(plaintext, key)

print("Texte clair       :", plaintext.hex())
print("Texte chiffre     :", ciphertext.hex())

# Verification
assert ciphertext.hex() == expected, "Erreur de chiffrement !"

# Dechiffrement
decrypted = decrypt_block(ciphertext, key)

print("Texte dechiffre   :", decrypted.hex())

assert decrypted == plaintext, "Erreur de dechiffrement !"

print("\nSUCCES : AES-128 fonctionne correctement !")
