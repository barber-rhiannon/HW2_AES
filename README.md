```
Author: Rhiannon Barber
Date: Nov. 19, 2025
```

# AES-128 Implementation

## Overview
This repository contains a modular implementation of the Advanced Encryption Standard (AES) using 128-bit keys. 
The implementation is written in Python, using the Pycharm IDE, without the use of external libraries. 
All AES functionality, including SubBytes, ShiftRows, MixColumns, AddRoundKey, and Key Expansion, is implemented manually according to the AES specifications.

---


### `aes.py`
Contains the AES-128 encryption routine and all core transformations.  
Includes:
- State initialization
- SubBytes
- ShiftRows
- MixColumns
- AddRoundKey
- AES-128 Key Expansion
- Final ciphertext construction

### `tables.py`
Contains the AES S-box and Rcon tables used for substitution and key expansion. These values are stored separately to maintain clarity and modularity.

### `test_nist.py`
Runs the official AES-128 Known Answer Test (KAT) published by NIST. This verifies that the implementation produces the expected ciphertext for a standard plaintext-key pair.

### `test_random_inputs.py`
Runs several randomized encryption tests to ensure the implementation behaves correctly with arbitrary but valid inputs.

### `test_hex.py`
Allows testing AES encryption using plaintext and key values provided as hexadecimal strings. This is useful for validating the implementation against external AES tools.

### `test_invalid_inputs.py`
Tests how the implementation behaves when provided with invalid input sizes or values. This is helpful for assessing robustness, and for evaluating student submissions.

---




