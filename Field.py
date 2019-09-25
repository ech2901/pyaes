from itertools import product, starmap


# TODO comment code
# TODO remake inverse property of GF class so it isn't a brute force approach

class GF(object):
    def __init__(self, val: int):
        """
        Galois(Finite) Field class that does most of the math behind the scenes

        :param val: int
        """

        if type(val) != int:
            raise TypeError(f'Expected <int> input and received a {type(val)}')

        self.int = val
        self.val = GF._toset_(val)

    @staticmethod
    def _toset_(val):
        """
        Break down val into powers of 2
        IE:

        input: 5
        output: {0, 2} # (2^2)+(2^0) = 5

        input: 30
        output: {1, 2, 3, 4} # (2^4)+(2^3)+(2^2)+(2^1) = 30

        :param val: int
        :return: set
        """
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
        """
        Convert param val into it's int representation
        and assign class properties appropriately

        :param val: set
        :return: GF
        """
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
        """
        return hexstring representation of the int property

        :return: str
        """
        return hex(self.int)

    @property
    def inverse(self):
        """
        Brute force finding the inverse
        of a given Galois Field value.


        :return: GF
        """

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
        """
        Multiply two GF objects together
        Does not maintain finite field.

        :param other: GF
        :return: GF
        """
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
        """
        xor the values of two GF objects

        :param other: GF
        :return: GF
        """
        return GF.fromset(self.val ^ other.val)

    def __mod__(self, other):
        """
        calculate the modulus of two GF objects

        :param other: GF
        :return: GF
        """
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

    def __str__(self):
        """
        return hex representation of the int property

        different from the hex property as this has no
        leading '0x' characters and is justified to the right
        so that there is a leading '0' when appropriate for a
        single byte.

        :return: str
        """

        return hex(self.int)[2:].rjust(2, "0")

    def __eq__(self, other):
        """
        Test equality of two GF objects

        :param other: GF
        :return: bool
        """
        out = True and type(self) == type(other)
        out = out and self.int == other.int
        out = out and self.val ^ other.val == set()

        return out

    def mul(self, other, modulus):
        """
        Return the product of two GF objects modulus another GF object

        :param other: GF
        :param modulus: GF
        :return: GF
        """


        return (self * other) % modulus


def sbox(gf):
    """
    Calculate the Rjindael S-Box of a GF object

    :param gf: GF
    :return: GF
    """
    def lrotate(shift):
        lrot = (val << shift) & 0xff
        lrot = lrot | (val >> (8 - shift))
        return lrot

    val = gf.inverse.int
    out = val ^ 0x63

    for i in range(1, 5):
        out = out ^ lrotate(i)

    return GF(out)


def invsbox(gf):
    """
    Calculate the Rjindael Inverse S-Box of a GF object

    :param gf: GF
    :return: GF
    """
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
