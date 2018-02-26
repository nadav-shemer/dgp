#!/usr/bin/python
import base64
import hashlib
import sys

def bytes_to_int(bytes_rep):
    """convert a string of bytes (in big-endian order) to a long integer

    :param bytes_rep: the raw bytes
    :type bytes_rep: str
    :return: the unsigned integer
    :rtype: long
    """
    return long(base64.b16encode(bytes_rep), 16)

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

def grab_xkcd(int_data, count):
    words = get_xkcd(int_data)
    return ''.join([s.capitalize() for s in words[:count]])

if len(sys.argv) != 3:
    print 'Usage: fingerprint.py <seed> <account>'
    sys.exit(0)

wordlist = get_wordlist()
seed = sys.argv[1]
account = sys.argv[2]
int_data = bytes_to_int(hashlib.sha256(seed + account).digest())
print grab_xkcd(int_data, 4)
