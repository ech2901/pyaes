# pyaes

## Description

This is my attempt to implement the AES encryption algorithm in Python 3.7.

This is my first real project that has taken a while to study and understand the mathematics behind the scenes in how it operates and also my first project uploaded to Github so that I can learn how to properly use version control software as well.



End goal is to be used in the creation of a password manager system.


## Installation

Package can be installed with pip via:

pip install ech2901-pyaes==1.2.1

## Simple Use Case
from pyaes.AES import ECB

ecb_mode = ECB()

ciphertext, salt = ecb_mode.encrypt(plaintext=b'test', password=b'password', size=128)

plaintext = ecb_mode.decrypt(ciphertext=ciphertext, password=b'password', size=128)
