
# AES-128 : implementation manuelle

# Multiplication dans GF(2^8)
def gf_mul(a, b):
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        high_bit = a & 0x80
        a = (a << 1) & 0xFF

        if high_bit:
            a ^= 0x1B

        b >>= 1

    return result


def gf_pow(a, power):
    result = 1

    while power:
        if power & 1:
            result = gf_mul(result, a)

        a = gf_mul(a, a)
        power >>= 1

    return result


def rotl8(value, shift):
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


# Construction de la S-Box
def create_sbox():
    sbox = []

    for value in range(256):
        inverse = gf_pow(value, 254) if value else 0

        transformed = (
            inverse
            ^ rotl8(inverse, 1)
            ^ rotl8(inverse, 2)
            ^ rotl8(inverse, 3)
            ^ rotl8(inverse, 4)
            ^ 0x63
        )

        sbox.append(transformed)

    return sbox


SBOX = create_sbox()

INV_SBOX = [0] * 256
for i, value in enumerate(SBOX):
    INV_SBOX[value] = i


RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]


# Expansion de la cle
def key_expansion(key):
    if len(key) != 16:
        raise ValueError("La cle AES-128 doit contenir 16 octets.")

    words = [
        list(key[i:i + 4])
        for i in range(0, 16, 4)
    ]

    for i in range(4, 44):
        temp = words[i - 1].copy()

        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]

        new_word = [
            words[i - 4][j] ^ temp[j]
            for j in range(4)
        ]

        words.append(new_word)

    round_keys = []

    for r in range(11):
        round_key = []

        for word in words[r * 4:(r + 1) * 4]:
            round_key.extend(word)

        round_keys.append(round_key)

    return round_keys


# Transformation AddRoundKey
def add_round_key(state, round_key):
    return [state[i] ^ round_key[i] for i in range(16)]


# Transformation SubBytes
def sub_bytes(state):
    return [SBOX[b] for b in state]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


# Transformation ShiftRows
def shift_rows(state):
    result = [0] * 16

    for row in range(4):
        for col in range(4):
            result[row + 4 * col] = state[
                row + 4 * ((col + row) % 4)
            ]

    return result


def inv_shift_rows(state):
    result = [0] * 16

    for row in range(4):
        for col in range(4):
            result[row + 4 * col] = state[
                row + 4 * ((col - row) % 4)
            ]

    return result


# Transformation MixColumns
def mix_columns(state):
    result = state.copy()

    for col in range(4):
        i = 4 * col
        a0, a1, a2, a3 = state[i:i + 4]

        result[i] = (
            gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
        )
        result[i + 1] = (
            a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
        )
        result[i + 2] = (
            a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
        )
        result[i + 3] = (
            gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)
        )

    return result


def inv_mix_columns(state):
    result = state.copy()

    for col in range(4):
        i = 4 * col
        a0, a1, a2, a3 = state[i:i + 4]

        result[i] = (
            gf_mul(a0, 14) ^ gf_mul(a1, 11)
            ^ gf_mul(a2, 13) ^ gf_mul(a3, 9)
        )
        result[i + 1] = (
            gf_mul(a0, 9) ^ gf_mul(a1, 14)
            ^ gf_mul(a2, 11) ^ gf_mul(a3, 13)
        )
        result[i + 2] = (
            gf_mul(a0, 13) ^ gf_mul(a1, 9)
            ^ gf_mul(a2, 14) ^ gf_mul(a3, 11)
        )
        result[i + 3] = (
            gf_mul(a0, 11) ^ gf_mul(a1, 13)
            ^ gf_mul(a2, 9) ^ gf_mul(a3, 14)
        )

    return result


# Chiffrement d'un bloc de 16 octets
def encrypt_block(plaintext, key):
    if len(plaintext) != 16:
        raise ValueError("Le bloc doit contenir 16 octets.")

    round_keys = key_expansion(key)
    state = list(plaintext)

    state = add_round_key(state, round_keys[0])

    for r in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return bytes(state)


# Dechiffrement d'un bloc de 16 octets
def decrypt_block(ciphertext, key):
    if len(ciphertext) != 16:
        raise ValueError("Le bloc doit contenir 16 octets.")

    round_keys = key_expansion(key)
    state = list(ciphertext)

    state = add_round_key(state, round_keys[10])

    for r in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return bytes(state)
