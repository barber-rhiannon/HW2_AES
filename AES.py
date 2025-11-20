'''
Author: Rhiannon Barber
Date: Nov. 19 2025
CS454: Homework 2 - AES Project

This program is written in Python and implements the AES-128 encryption
algorithm. The implementation avoids external libraries and follows the
algorithmic specification for AES, including all core transformations and
the 128-bit key expansion process.

TO RUN THIS PROGRAM:
This file provides the AES building blocks and can be used by importing the
module into a separate script. Testing scripts included in this repository
can be executed as follows:

python3 test_nist.py
python3 test_random_inputs.py
python3 test_hex.py
python3 test_invalid_inputs.py

Each test script demonstrates a different aspect of the AES implementation,
including correctness verification, randomized encryption testing, and
invalid input behavior analysis.

'''

from tables import SBOX, RCON


def galois_multiply(a, b):
    '''
    Performs multiplication of two bytes within the Galois Field GF(2^8)
    using the AES-specific reduction polynomial. This operation is used
    during the MixColumns transformation.
    '''
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return product


def sub_bytes(state):
    '''
    Applies the AES SubBytes transformation to the 4x4 state matrix by
    substituting each byte using the AES S-box.
    '''
    return [[SBOX[value] for value in row] for row in state]


def shift_rows(state):
    '''
    Performs the AES ShiftRows transformation by cyclically shifting each
    row of the state matrix to the left by an increasing offset.
    '''
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3]
    ]


def mix_single_column(column):
    '''
    Applies the AES MixColumns transformation to a single four-byte column,
    producing a new column based on finite field multiplication and XOR.
    '''
    a0, a1, a2, a3 = column
    return [
        galois_multiply(a0, 2) ^ galois_multiply(a1, 3) ^ a2 ^ a3,
        a0 ^ galois_multiply(a1, 2) ^ galois_multiply(a2, 3) ^ a3,
        a0 ^ a1 ^ galois_multiply(a2, 2) ^ galois_multiply(a3, 3),
        galois_multiply(a0, 3) ^ a1 ^ a2 ^ galois_multiply(a3, 2)
    ]


def mix_columns(state):
    '''
    Applies the MixColumns transformation to each column of the state matrix
    by invoking the column-level MixColumns function.
    '''
    mixed = [[0]*4 for _ in range(4)]
    for col in range(4):
        a = [state[row][col] for row in range(4)]
        mixed_column = [
            galois_multiply(a[0], 2) ^ galois_multiply(a[1], 3) ^ a[2] ^ a[3],
            a[0] ^ galois_multiply(a[1], 2) ^ galois_multiply(a[2], 3) ^ a[3],
            a[0] ^ a[1] ^ galois_multiply(a[2], 2) ^ galois_multiply(a[3], 3),
            galois_multiply(a[0], 3) ^ a[1] ^ a[2] ^ galois_multiply(a[3], 2)
        ]
        for row in range(4):
            mixed[row][col] = mixed_column[row]
    return mixed


def add_round_key(state, round_key):
    '''
    Combines the current state matrix with the corresponding round key using
    a bitwise XOR operation. This operation is performed in every AES round.
    '''
    return [
        [state[row][col] ^ round_key[row][col] for col in range(4)]
        for row in range(4)
    ]


def rotate_word(word):
    '''
    Rotates a four-byte word left by one byte. This operation is used during
    the AES Key Expansion process.
    '''
    return word[1:] + word[:1]


def substitute_word(word):
    '''
    Applies the AES S-box substitution to each byte of a four-byte word.
    This operation is used during the AES Key Expansion process.
    '''
    return [SBOX[b] for b in word]


def expand_key(key_bytes):
    '''
    Expands a 16-byte AES key into 44 four-byte words, forming the
    11 round keys required for AES-128 encryption. This includes
    the RotWord, SubWord, and Rcon operations.
    '''
    words = [list(key_bytes[i*4:i*4+4]) for i in range(4)]
    for index in range(4, 44):
        temp = words[index - 1].copy()
        if index % 4 == 0:
            temp = rotate_word(temp)
            temp = substitute_word(temp)
            temp[0] ^= RCON[index // 4]
        previous = words[index - 4]
        words.append([temp[i] ^ previous[i] for i in range(4)])
    round_keys = []
    for i in range(11):
        block = words[i*4:(i+1)*4]
        matrix = [[block[col][row] for col in range(4)] for row in range(4)]
        round_keys.append(matrix)
    return round_keys


def aes_encrypt_block(plaintext_bytes, key_bytes):
    '''
    Encrypts a single 16-byte plaintext block using AES-128. The function
    performs the initial AddRoundKey step, nine main AES rounds, and one
    final round that omits the MixColumns transformation. The resulting
    ciphertext is returned as a list of 16 bytes.
    '''
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = plaintext_bytes[i]
    round_keys = expand_key(key_bytes)
    state = add_round_key(state, round_keys[0])
    for round_number in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_number])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    ciphertext = [0]*16
    for col in range(4):
        for row in range(4):
            ciphertext[col*4 + row] = state[row][col]
    return ciphertext
