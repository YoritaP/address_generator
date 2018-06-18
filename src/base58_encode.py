# encoding:utf-8
import hashlib

# base58 encode
b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def base58_encode(s, version=0):
    vs = chr(version) + str(s)
    # checksum バージョン+アドレスのsha256を2回かけたやつの先頭バイト
    check = hashlib.sha256(hashlib.sha256(vs).digest()).digest()[:4]
    s = vs + check
    n = int('0x' + s.encode('hex'), 16)
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(b58_digits[r]))
    res = ''.join(l)
 
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res
