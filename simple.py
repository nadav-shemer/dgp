#!/usr/bin/python3
#from werkzeug.security import pbkdf2_bin, pbkdf2_hex
import werkzeug
import hashlib
import base64
import os
import sys
import typing as t

SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
DEFAULT_PBKDF2_ITERATIONS = 260000

# Copied from now-deprecated API in Werkzeug
def pbkdf2_hex(
    data: t.Union[str, bytes],
    salt: t.Union[str, bytes],
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    keylen: t.Optional[int] = None,
    hashfunc: t.Optional[t.Union[str, t.Callable]] = None,
) -> str:
    """Like :func:`pbkdf2_bin`, but returns a hex-encoded string.
    :param data: the data to derive.
    :param salt: the salt for the derivation.
    :param iterations: the number of iterations.
    :param keylen: the length of the resulting key.  If not provided,
                   the digest size will be used.
    :param hashfunc: the hash function to use.  This can either be the
                     string name of a known hash function, or a function
                     from the hashlib module.  Defaults to sha256.
    .. deprecated:: 2.0
        Will be removed in Werkzeug 2.1. Use :func:`hashlib.pbkdf2_hmac`
        instead.
    .. versionadded:: 0.9
    """
    return pbkdf2_bin(data, salt, iterations, keylen, hashfunc).hex()


# Copied from old code: "'pbkdf2_bin' is deprecated and will be removed in Werkzeug 2.1. Use 'hashlib.pbkdf2_hmac()' instead.",
def pbkdf2_bin(
    data: t.Union[str, bytes],
    salt: t.Union[str, bytes],
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    keylen: t.Optional[int] = None,
    hashfunc: t.Optional[t.Union[str, t.Callable]] = None,
) -> bytes:
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`. It iterates `iterations` times and produces a
    key of `keylen` bytes. By default, SHA-256 is used as hash function;
    a different hashlib `hashfunc` can be provided.
    :param data: the data to derive.
    :param salt: the salt for the derivation.
    :param iterations: the number of iterations.
    :param keylen: the length of the resulting key.  If not provided
                   the digest size will be used.
    :param hashfunc: the hash function to use.  This can either be the
                     string name of a known hash function or a function
                     from the hashlib module.  Defaults to sha256.
    .. deprecated:: 2.0
        Will be removed in Werkzeug 2.1. Use :func:`hashlib.pbkdf2_hmac`
        instead.
    .. versionadded:: 0.9
    """
    if isinstance(data, str):
        data = data.encode("utf8")

    if isinstance(salt, str):
        salt = salt.encode("utf8")

    if not hashfunc:
        hash_name = "sha256"
    elif callable(hashfunc):
        hash_name = hashfunc().name
    else:
        hash_name = hashfunc

    return hashlib.pbkdf2_hmac(hash_name, data, salt, iterations, keylen)



def bytes_to_int(bytes_rep):
    """convert a string of bytes (in big-endian order) to an integer

    :param bytes_rep: the raw bytes
    :type bytes_rep: str
    :return: the unsigned integer
    :rtype: int
    """
    return int(bytes_rep.hex(), 16)

dec_digit_to_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#base58_digit_to_dec = { b58:dec for dec,b58 in enumerate(dec_digit_to_base58) }

def get_base58(int_data):
    res = ''
    while int_data > 0:
        mod = int_data % 58
        int_data = int_data // 58
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
        int_data = int_data // 2048
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
    print('seed: {}, account: {}, name: {}'.format(seed, account, name))
    for entry_type in 'hex','hexlong','alnum','alnumlong','base58','base58long','xkcd','xkcdlong':
        print('{}: {}'.format(entry_type, test_vector_wrapper(seed, account, name, entry_type)))

def some_types(seed, account, name):
    print('seed: {}, account: {}, name: {}'.format(seed, account, name))
    for entry_type in 'hexlong','alnum','xkcdlong':
        print('{}: {}'.format(entry_type, test_vector_wrapper(seed, account, name, entry_type)))

if len(sys.argv) == 1:
    print('Usage: simple.py test-vectors')
    print('OR simple.py <seed> <account> <name> <type>')
    sys.exit(0)

if sys.argv[1] == 'test-vectors':
    print('a:aa:alnum: {}'.format(test_vector_wrapper("a", "", "aa", "alnum")))
    print('aa:a:alnum: {}'.format(test_vector_wrapper("aa", "", "a", "alnum")))
    print('a:aa:base58: {}'.format(test_vector_wrapper("a", "", "aa", "base58")))
    print('a:aa:alnumlong: {}'.format(test_vector_wrapper("a", "", "aa", "alnumlong")))
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
    print('{}:{}:{}:{}'.format(account,name,entry_type,generate(seed,name,entry_type,account)))
