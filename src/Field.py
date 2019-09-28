from itertools import product, starmap
# itertools functions only used in __mul__ function currently

# TODO comment code
# TODO remake inverse property of GF class so it isn't a brute force approach
# TODO Remove need for val property in GF class

class GF(object):
    def __init__(self, val: int):
        """
        Galois(Finite) Field class that does most of the math behind the scenes

        :param val: int
        """

        if type(val) != int:
            raise TypeError(f'Expected <int> input and received a {type(val)}')

        self.int = val  # Used on occasion to short circuit some operations (IE: Multiply by one operation)
        self.val = GF._toset_(val)  # Currently used to do all the real math

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
        out = set()  # Empty set that will be the output
        index = 0  # What power of 2 we are working on
        while val:
            if val & 1:
                # Check if this power of 2 is a 1 or 0
                out.add(index)  # Add to the output
            index = index + 1  # Increment which power of 2 we're operating on
            val = val >> 1  # Shift val to the right once
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
            # Make sure we're trying to initialize from a set not any other indexible object
            raise TypeError(f'Expected <set> input parameter and recieved a {type(val)}')

        out = GF(0)  # Base output
        for i in val:
            if type(i) != int:  # Make sure that every item in the set is only an int object
                raise TypeError(f'Expected <int> input and received a {type(i)}')
            out.int = out.int | (1 << i)  # add each power of 2 to the int object of the output

        out.val = val  # Assign the given val object to the output val property
        return out

    @property
    def inverse(self):
        """
        Brute force finding the inverse
        of a given Galois Field value.


        :return: GF
        """

        if self.int == 0:
            # 0 has no inverse, so return itself
            return self
        if self.int == 1:
            # Inverse of 1 is 1
            return self

        # Honestly, this is a brute force approach to finding an inverse.
        # Will replace later with a better solution
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
            # Make sure that we're only operating on GF objects
            raise TypeError

        if self.int == 0 or other.int == 1:
            # Anything times 0 is zero
            # Anything times 1 is the value
            return self
        if other.int == 0 or self.int == 1:
            # Anything times 0 is zero
            # Anything times 1 is the value
            return other

        out = set()  # Base output
        # Get all combinations of these powers of 2
        # IE: product({0, 1}, {1, 2, 3}) => ((0,1), (0,2), (0,3), (1,1), (1,2), (1,3))
        prod = product(self.val, other.val)
        for val in starmap(lambda a, b: a + b, prod):
            # Add each value pair together and xor with the output
            # Continuing from previous example will become
            # (1, 2, 3, 2, 3, 4) => {1, 4}
            out = out ^ {val}
        return GF.fromset(out)

    def __xor__(self, other):
        """
        xor the values of two GF objects

        :param other: GF
        :return: GF
        """
        # Just the xoring of two sets and assigning that to a GF object
        # IE: {0, 3} ^ {0, 1} => {1, 3} => GF.fromset({1, 3}) == GF(10)
        return GF.fromset(self.val ^ other.val)

    def __mod__(self, other):
        """
        calculate the modulus of two GF objects

        :param other: GF
        :return: GF
        """
        if type(other) != type(self) and type(self) == GF:
            # Make sure we're working on GF objects
            raise TypeError

        if self.int == 0:
            # 0 modulus anything is zero
            return self
        if other.int == 0:
            # Technically I should raise a ZeroDivisionError but I don't know how that'll go yet
            return other


        # Get the max power of 2 we're working with for both this GF and the other GF
        max1 = max(self.val)
        max2 = max(other.val)

        # Start the output is a copy of this GF
        out = self

        while max1 >= max2:  # While this GF is larger than the other
            # xor values
            out = out ^ (other * GF.fromset({max1 - max2}))
            # Check to see largest power of 2 in new output or 0 if an empty set
            max1 = max(out.val) if len(out.val) else 0

        return out

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
        # rotate bits :shift: bits to the left
        lrot = (val << shift) & 0xff
        lrot = lrot | (val >> (8 - shift))
        return lrot

    # Using the inverse of the given GF object
    val = gf.inverse.int
    out = val ^ 0x63

    for i in range(1, 5):
        # repeatedly shift the bits to the left and xor with output
        out = out ^ lrotate(i)

    return GF(out)


def invsbox(gf):
    """
    Calculate the Rjindael Inverse S-Box of a GF object

    :param gf: GF
    :return: GF
    """
    def lrotate(shift):
        # rotate bits :shift: bits to the left
        lrot = (val << shift) & 0xff
        lrot = lrot | (val >> (8 - shift))
        return lrot

    val = gf.int
    out = 0x5

    # repeatedly shift the bits to the left and xor with output
    out = out ^ lrotate(1)
    out = out ^ lrotate(3)
    out = out ^ lrotate(6)

    # Return the inverse of the calculated GF object
    return GF(out).inverse


modulus = GF(283)
