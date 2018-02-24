#!/usr/bin/python
from werkzeug.security import pbkdf2_bin, pbkdf2_hex
import base64
import os
import sys

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

def get_base58(int_data):
    res = ''
    while int_data > 0:
        mod = int_data % 58
        int_data = int_data / 58
        res = res + dec_digit_to_base58[mod]
    return res

# Because password 'strength' checkers are dicks
def is_alnum(string):
    has_lower = False
    has_upper = False
    has_digit = False
    for i in range(len(string)):
        if string[i] >= '0' and string[i] <= '9':
            has_digit = True
        if string[i] >= 'a' and string[i] <= 'z':
            has_lower = True
        if string[i] >= 'A' and string[i] <= 'Z':
            has_upper = True
    return has_digit and has_lower and has_upper

def grab_alnum(int_data, length):
    raw = get_base58(int_data)
    while True:
        # We assume there is a substring that will pass. Otherwise we explode
        assert len(raw) > length
        res = raw[:length]
        if is_alnum(res):
            return res
        raw = raw[1:]

def gen_large_int(seed, name, secret):
    # keylen=digest-len hashfunc=sha256
    bin_data = pbkdf2_bin(seed + secret, name, iterations=42000, hashfunc='sha1', keylen=40)
    int_data = bytes_to_int(bin_data)
    return int_data

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

def generate(seed, name, entry_type, secret):
    if entry_type == 'hex':
        res = pbkdf2_hex(seed + secret, name, iterations=42000, hashfunc='sha1', keylen=40)
        res = res[:8]
    elif entry_type == 'hexlong':
        res = pbkdf2_hex(seed + secret, name, iterations=42000, hashfunc='sha1', keylen=40)
        res = res[:16]
    elif entry_type == 'alnum':
        int_data = gen_large_int(seed, name, secret)
        res = grab_alnum(int_data, 8)
    elif entry_type == 'alnumlong':
        int_data = gen_large_int(seed, name, secret)
        res = grab_alnum(int_data, 12)
    elif entry_type == 'base58':
        int_data = gen_large_int(seed, name, secret)
        res = get_base58(int_data)[:8]
    elif entry_type == 'base58long':
        int_data = gen_large_int(seed, name, secret)
        res = get_base58(int_data)[:12]
    elif entry_type == 'xkcd':
        int_data = gen_large_int(seed, name, secret)
        res = grab_xkcd(int_data, 4)
    elif entry_type == 'xkcdlong':
        int_data = gen_large_int(seed, name, secret)
        res = grab_xkcd(int_data, 6)
    else:
        res = 'unknown type'
    return res

def test_vector_wrapper(seed, account, name, entry_type):
    return generate(seed, name, entry_type, account)

def all_types(seed, account, name):
    print 'seed: {}, account: {}, name: {}'.format(seed, account, name)
    for entry_type in 'hex','hexlong','alnum','alnumlong','base58','base58long','xkcd','xkcdlong':
        print '{}: {}'.format(entry_type, test_vector_wrapper(seed, account, name, entry_type))

def some_types(seed, account, name):
    print 'seed: {}, account: {}, name: {}'.format(seed, account, name)
    for entry_type in 'hexlong','alnum','xkcdlong':
        print '{}: {}'.format(entry_type, test_vector_wrapper(seed, account, name, entry_type))

if len(sys.argv) == 1:
    print 'Usage: simple.py test-vectors'
    print 'OR simple.py <seed> <account> <name> <type>'
    sys.exit(0)

if sys.argv[1] == 'test-vectors':
    print 'a:aa:alnum: {}'.format(test_vector_wrapper("a", "", "aa", "alnum"))
    print 'a:aa:base58: {}'.format(test_vector_wrapper("a", "", "aa", "base58"))
    print 'a:aa:alnumlong: {}'.format(test_vector_wrapper("a", "", "aa", "alnumlong"))
    P = "passwordPASSWORDpassword"
    S = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
    all_types(P, "", S)
    all_types("pass", "word", "salt")
    some_types("A"*64, "", "salt")
    some_types("A"*65, "", "salt")
    some_types("A"*64, "", "B"*64)
    some_types("A"*64, "", "B"*65)
    some_types("A"*65, "", "B"*64)
    some_types("A"*65, "", "B"*65)
    some_types("A"*64, "default", "salt")
    some_types("A"*65, "default", "salt")
    some_types("A"*64, "default", "B"*64)
    some_types("A"*64, "default", "B"*65)
    some_types("A"*65, "default", "B"*64)
    some_types("A"*65, "default", "B"*65)
    some_types("A"*64, "test", "salt")
    some_types("A"*65, "test", "salt")
    some_types("A"*64, "test", "B"*64)
    some_types("A"*64, "test", "B"*65)
    some_types("A"*65, "test", "B"*64)
    some_types("A"*65, "test", "B"*65)
else:
    seed = sys.argv[1]
    account = sys.argv[2]
    name = sys.argv[3]
    entry_type = sys.argv[4]
    print '{}:{}:{}:{}'.format(account,name,entry_type,generate(seed,name,entry_type,account))
