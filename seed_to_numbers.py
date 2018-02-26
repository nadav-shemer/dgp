#!/usr/bin/python
import sys

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

if len(sys.argv) == 1:
    print 'Usage: seed_to_numbers.py <seed>'
    sys.exit(0)

wordlist = get_wordlist()
seed = sys.argv[1:]
seednums = []
for sword in seed:
    i = 0
    found = False
    for word in wordlist:
        if word == sword:
            seednums.append(i)
            found = True
            break
        i += 1
    if not found:
        print 'could not find index for {}'.format(sword)
        sys.exit(1)

print seednums
