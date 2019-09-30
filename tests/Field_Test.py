import unittest

from src.Field import GF, modulus
from src.Field import sbox, invsbox


class TestFieldMethods(unittest.TestCase):

    def test_int_nofail(self):
        # Test to make sure all possible ints can be made
        # into GF objects
        for i in range(131_071):
            val = GF(i)
            self.assertIsNotNone(val)
            self.assertIsInstance(val, GF)
            self.assertIsNotNone(val.int)
            self.assertEqual(val.int, i)
            self.assertIsNotNone(val.val)

    def test_int_fail(self):
        # Test to make sure that -only- ints that are greater than
        # or equal to 0 may be created and not any other data type
        for i in [-1, 'a', True, False, b'help', lambda x: 0, None]:
            self.assertRaises(Exception, GF, i)

    def test_set_nofail(self):
        for i in ({0}, {1, 2, 3}, {5, 16, 10}):
            val = GF.fromset(i)
            self.assertIsNotNone(val)
            self.assertIsInstance(val, GF)
            self.assertIsNotNone(val.int)
            self.assertIsNotNone(val.val)
            self.assertEqual(val.val, i)

    def test_set_fail(self):
        for i in ({True, False, False}, {-1, 2, 0}, {b'abc'}, {'abc'}, {'a', 'b', 'c'}):
            self.assertRaises(Exception, GF.fromset, i)

    def test_int_extra_paramaters_fail(self):
        # Test to make sure that extra parameters raise an error
        # when trying to create a GF object
        a = [1, 2]
        for i in range(3, 100):
            self.assertRaises(Exception, GF, *a)
            a.append(i)

    def test_set_extra_parameters_fail(self):
        a = [set(), set()]
        for _ in range(3, 100):
            self.assertRaises(Exception, GF.fromset, *a)
            a.append(set())

    def test_mul_nofail(self):
        # Test multiplication to make sure it works as expected
        # Values used calculated with pen & paper first
        param_a = (set(), set(), {0}, {1, 2, 3})
        param_b = (set(), {0, 1, 2, 3}, {1, 2, 3, 4}, {4, 5, 6})
        param_c = (set(), set(), {1, 2, 3, 4}, {5, 7, 9})

        for a, b, c in zip(param_a, param_b, param_c):
            self.assertEqual(GF.fromset(a) * GF.fromset(b), GF.fromset(c))

    def test_mul_fail(self):
        # Test multiplication to make sure -only- GF objects
        # can multiply together
        param_a = (set(), {0}, {1, 2, 3}, )
        param_b = (0, 1, -1, True, False, 'abc', b'abc', (1, 2, 3), (-1, -2, -3))
        for a in param_a:
            for b in param_b:
                self.assertRaises(Exception, GF.fromset(a).__mul__, b)

    def test_mod_nofail(self):
        # Test modulus operations to make sure works as expected
        # Values used calculated with pen & paper first
        param_a = (set(), {0}, {1, 2, 3, 4}, {7, 4, 6, 2, 0})
        param_b = ({0}, {4, 3}, {2, 0}, {4, 3})
        param_c = (set(), {0}, set(), {3, 2, 0})

        for a, b, c in zip(param_a, param_b, param_c):
            self.assertEqual(GF.fromset(a) % GF.fromset(b), GF.fromset(c))

    def test_mod_fail(self):
        # Test modulus to make sure -only- GF objects
        # can multiply together
        param_a = (set(), {0}, {1, 2, 3, 4}, {7, 4, 6, 2, 0})
        param_b = (0, 1, -1, True, False, 'abc', b'abc', (1, 2, 3), (-1, -2, -3))
        for a in param_a:
            for b in param_b:
                self.assertRaises(Exception, GF.fromset(a).__mod__, b)

    def test_xor_nofail(self):
        # Test xor operations to make sure works as expected
        # Values used calculated with pen & paper first
        param_a = (set(), {0}, {1, 2, 3, 4}, {1, 3, 5, 7})
        param_b = (set(), {0}, {3, 4, 5, 6}, {2, 4, 6, 8})
        for a in param_a:
            for b in param_b:
                self.assertEqual(GF.fromset(a) ^ GF.fromset(b), GF.fromset(a ^ b))

    def test_xor_fail(self):
        # Test xor to make sure -only- GF objects
        # can multiply together
        param_a = (set(), {0}, {1, 2, 3, 4}, {7, 4, 6, 2, 0})
        param_b = (0, 1, -1, True, False, 'abc', b'abc', (1, 2, 3), (-1, -2, -3))
        for a in param_a:
            for b in param_b:
                self.assertRaises(Exception, GF.fromset(a).__xor__, b)

    def test_inverse_nofail(self):
        # Test inversion of GF objects
        # Needs to work for S-box & inverse S-Box operations
        test_param = GF(1)
        # Test to see if GF(i) * (1/GF(i)) == 1
        for i in range(1, 256):
            val = GF(i)
            self.assertEqual(val.mul(val.inverse, modulus), test_param)


class TestSboxFunctions(unittest.TestCase):

    def test_inputs_nofail(self):
        # Test to make sure S-box and inverse S-box
        # are able to cancel each other out
        for i in range(256):
            val = GF(i)
            self.assertEqual(invsbox(sbox(val)), val)

    def test_inputs_fail(self):
        # Test to make sure that only GF objects can be used
        for i in (0, 1, -1, True, False, 'abc', b'abc', (1, 2, 3), (-1, -2, -3)):
            self.assertRaises(Exception, sbox, i)
            self.assertRaises(Exception, invsbox, i)


if __name__ == '__main__':
    # Run all the tests
    Field_Suite = unittest.TestSuite()

    Field_Suite.addTest(TestFieldMethods())
    Field_Suite.addTest(TestSboxFunctions())

    Field_Suite.run(unittest.TestResult())
