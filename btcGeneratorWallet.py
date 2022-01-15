from hashlib import sha256
from typing import Union


class Point(object):
    def __init__(self, _x, _y, _order=None):
        self.x, self.y, self.order = _x, _y, _order

    def calc(self, top, bottom, other_x):
        ll = (top * inverse_mod(bottom)) % p
        x3 = (ll * ll - self.x - other_x) % p
        return Point(x3, (ll * (self.x - x3) - self.y) % p)

    def double(self):
        if self == INFINITY:
            return INFINITY
        return self.calc(3 * self.x * self.x, 2 * self.y, self.x)

    def __add__(self, other):
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        if self.x == other.x:
            if (self.y + other.y) % p == 0:
                return INFINITY
            return self.double()
        return self.calc(other.y - self.y, other.x - self.x, other.x)

    def __mul__(self, e):
        if self.order:
            e %= self.order
        if e == 0 or self == INFINITY:
            return INFINITY
        result, q = INFINITY, self
        while e:
            if e & 1:
                result += q
            e, q = e >> 1, q.double()
        return result

    def __str__(self):
        if self == INFINITY:
            return "infinity"
        return "%x %x" % (self.x, self.y)


p, INFINITY = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    Point(None, None),
)  # secp256k1
g = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)


def inverse_mod(a):
    if a < 0 or a >= p:
        a = a % p
    c, d, uc, vc, ud, vd = a, p, 1, 0, 0, 1
    while c:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc
    if ud > 0:
        return ud
    return ud + p


# Thanks for this snippet to David Keijser
# https://github.com/keis/base58/

BITCOIN_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def scrub_input(v: Union[str, bytes]) -> bytes:
    if isinstance(v, str):
        v = v.encode("ascii")
    return v


def b58encode_int(
    i: int, default_one: bool = True, alphabet: bytes = BITCOIN_ALPHABET
) -> bytes:
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    string = b""
    while i:
        i, idx = divmod(i, 58)
        string = alphabet[idx : idx + 1] + string
    return string


def b58encode(v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET) -> bytes:
    """
    Encode a string using Base58
    """
    v = scrub_input(v)

    nPad = len(v)
    v = v.lstrip(b"\0")
    nPad -= len(v)

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8
    result = b58encode_int(acc, default_one=False, alphabet=alphabet)
    return alphabet[0:1] * nPad + result


def b58decode_int(v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET) -> int:
    """
    Decode a Base58 encoded string as an integer
    """
    v = v.rstrip()
    v = scrub_input(v)

    decimal = 0
    for char in v:
        decimal = decimal * 58 + alphabet.index(char)
    return decimal


def b58decode(v: Union[str, bytes], alphabet: bytes = BITCOIN_ALPHABET) -> bytes:
    """
    Decode a Base58 encoded string
    """
    v = v.rstrip()
    v = scrub_input(v)

    origlen = len(v)
    v = v.lstrip(alphabet[0:1])
    newlen = len(v)

    acc = b58decode_int(v, alphabet=alphabet)

    result = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.append(mod)
    return b"\0" * (origlen - newlen) + bytes(reversed(result))
