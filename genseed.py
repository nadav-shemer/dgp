#!/usr/bin/python
import base64
import os

def bytes_to_int(bytes_rep):
    """convert a string of bytes (in big-endian order) to a long integer

    :param bytes_rep: the raw bytes
    :type bytes_rep: str
    :return: the unsigned integer
    :rtype: long
    """
    return long(base64.b16encode(bytes_rep), 16)

dec_digit_to_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#base58_digit_to_dec = { b58:dec for dec,b58 in enumerate(dec_digit_to_base58) }

def get_wordlist():
    with open('english.txt') as f:
        lines = f.readlines()
    return [line.rstrip() for line in lines]

def get_xkcd(int_data):
    wordlist = get_wordlist()
    res = []
    while int_data > 0:
        mod = int_data % 2048
        int_data = int_data / 2048
        res.append(wordlist[mod])
    return res

bin_data = os.urandom(40)
int_data = bytes_to_int(bin_data)
words = get_xkcd(int_data)
print '{} words:'.format(len(words))
print ' '.join(words)
