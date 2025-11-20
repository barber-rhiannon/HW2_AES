import pytest
from AES import (
    sub_bytes, shift_rows, mix_columns, add_round_key,
    expand_key, aes_encrypt_block
)
from tables import SBOX


def test_subbytes_all_values():
    for byte in range(256):
        assert SBOX[byte] == sub_bytes([[byte]])[0][0]


def test_shiftrows_pattern():
    state = [
        [0x00, 0x01, 0x02, 0x03],
        [0x10, 0x11, 0x12, 0x13],
        [0x20, 0x21, 0x22, 0x23],
        [0x30, 0x31, 0x32, 0x33]
    ]
    shifted = shift_rows(state)
    assert shifted == [
        [0x00, 0x01, 0x02, 0x03],
        [0x11, 0x12, 0x13, 0x10],
        [0x22, 0x23, 0x20, 0x21],
        [0x33, 0x30, 0x31, 0x32]
    ]


def test_mixcolumns_known():
    state = [
        [0xdb, 0x13, 0x53, 0x45],
        [0xf2, 0x0a, 0x22, 0x5c],
        [0x01, 0x01, 0x01, 0x01],
        [0xc6, 0xc6, 0xc6, 0xc6]
    ]
    expected = [
        [0x8e, 0x4d, 0xa1, 0xbc],
        [0x9f, 0xdc, 0x58, 0x9d],
        [0x01, 0x01, 0x01, 0x01],
        [0xc6, 0xc6, 0xc6, 0xc6]
    ]
    assert mix_columns(state) == expected


def test_addroundkey_identity():
    state = [[i for i in range(4)] for _ in range(4)]
    zero_key = [[0x00] * 4 for _ in range(4)]
    assert add_round_key(state, zero_key) == state


def test_addroundkey_xor_behavior():
    state = [[1, 2, 3, 4] for _ in range(4)]
    key = [[0xFF] * 4 for _ in range(4)]
    result = add_round_key(state, key)
    for r in range(4):
        for c in range(4):
            assert result[r][c] == (state[r][c] ^ 0xFF)


def test_key_expansion_shape():
    key = [0x00] * 16
    expanded = expand_key(key)
    assert len(expanded) == 11
    for round_key in expanded:
        assert len(round_key) == 4
        for row in round_key:
            assert len(row) == 4


def test_invalid_plaintext_length_short():
    with pytest.raises(Exception):
        aes_encrypt_block([0] * 10, [0] * 16)


def test_invalid_plaintext_length_long():
    result = aes_encrypt_block([0] * 20, [0] * 16)
    assert len(result) == 16


def test_invalid_key_length_short():
    with pytest.raises(Exception):
        aes_encrypt_block([0] * 16, [0] * 5)


def test_invalid_key_length_long():
    result = aes_encrypt_block([0] * 16, [0] * 20)
    assert len(result) == 16


def test_invalid_byte_range():
    with pytest.raises(Exception):
        aes_encrypt_block([999] * 16, [0] * 16)


def test_randomized_plaintext_key():
    import random
    for _ in range(100):
        plaintext = [random.randint(0,255) for _ in range(16)]
        key = [random.randint(0,255) for _ in range(16)]
        output = aes_encrypt_block(plaintext, key)
        assert len(output) == 16
        assert all(0 <= b <= 255 for b in output)
