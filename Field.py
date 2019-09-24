from itertools import product, starmap

# TODO comment code
# TODO create docstrings
# TODO format according to PEP 8

class GF(object):
    def __init__(self, val: int):

        if type(val) != int:
            raise TypeError(f'Expected <int> input and received a {type(val)}')

        self.int = val
        self.val = GF._toset_(val)

    @staticmethod
    def _toset_(val):
        out = set()
        index = 0
        while val:
            if val & 1:
                out.add(index)
            index = index + 1
            val = val >> 1
        return out

    @classmethod
    def fromset(cls, val):
        if type(val) != set:
            raise TypeError(f'Expected <set> input parameter and recieved a {type(val)}')

        out = GF(0)
        for i in val:
            if type(i) != int:
                raise TypeError(f'Expected <int> input and received a {type(i)}')
            out.int = out.int | (1 << i)


        out.val = val
        return out

    @property
    def hex(self):
        return hex(self.int)

    @property
    def inverse(self):
        if self.int == 0:
            return self
        if self.int == 1:
            return self
        modulus = GF(283)
        for i in range(2, 256):
            out = GF(i)
            if self.mul(out, modulus).int == 1:
                return out

    def __mul__(self, other):

        if type(other) != type(self):
            raise TypeError

        if self.int == 0:
            return self
        if other.int == 0:
            return other

        out = set()
        prod = product(self.val, other.val)
        for val in starmap(lambda a, b: a + b, prod):
            out = out ^ {val}
        return GF.fromset(out)

    def __xor__(self, other):
        return GF.fromset(self.val ^ other.val)

    def __mod__(self, other):
        def add(addition):
            out = set()
            for i in other.val:
                out = out ^ {i + addition}
            return out

        if type(other) != type(self):
            raise TypeError

        if self.int == 0:
            return self
        if other.int == 0:
            return other


        max1 = max(self.val)
        max2 = max(other.val)

        out = self.val

        while max1 >= max2:
            out = out ^ add(max1 - max2)
            max1 = max(out ^ {-1})

        return GF.fromset(out)

    def __repr__(self):
        return self.val.__repr__()

    def __str__(self):
        return hex(self.int)[2:].rjust(2, "0")

    def __eq__(self, other):
        out = True and type(self) == type(other)
        out = out and self.int == other.int
        out = out and self.val ^ other.val == set()

        return out


    def mul(self, other, modulus):
        return (self * other) % modulus


def sbox(gf):
    def lrotate(shift):
        lrot = (val << shift) & 0xff
        lrot = lrot | (val >> (8-shift))
        return lrot
    val = gf.inverse.int
    out = val ^ 0x63

    for i in range(1, 5):
        out = out ^ lrotate(i)

    return GF(out)

def invsbox(gf):
    def lrotate(shift):
        lrot = (val << shift) & 0xff
        lrot = lrot | (val >> (8 - shift))
        return lrot

    val = gf.int
    out = 0x5

    out = out ^ lrotate(1)
    out = out ^ lrotate(3)
    out = out ^ lrotate(6)

    return GF(out).inverse


modulus = GF(283)

