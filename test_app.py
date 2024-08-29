#!/usr/bin/env python3

"""PwnedWord Test App: Unit testing using unittest.
"""


# Import modules
import unittest
import pwnedcheck
import pwgen
import requests


class Test(unittest.TestCase):
    # Check if input is strings, everything else gets binned as None
    def test_type(self):
        self.assertTrue(pwnedcheck.check_status("123"))
        self.assertFalse(pwnedcheck.check_status("😀😁😂汉字"))
        self.assertTrue(pwnedcheck.check_status(123))
        self.assertIsNone(pwnedcheck.check_status(None))
        self.assertIsNone(pwnedcheck.check_status(True))

    # Check if we get a 200 from the server
    def test_connection(self):
        password_list_requested = requests.get(
                "https://api.pwnedpasswords.com/range/{}".format(
                    "40BD0"))
        self.assertEqual(password_list_requested.status_code, 200)

    # Check for non existent file
    def test_file(self):
        self.assertEqual(pwnedcheck.check_list("pwlist1.txt"), None)
        self.assertEqual(pwnedcheck.check_list("pwlist.txt"),
                        {'123456': True, 'password': True,
                        'AIUFBNalf/(((!(22': False})

    # Check if generated password length is at least 1 and an integer
    def test_gen(self):
        self.assertIsNone(pwgen.generate_password(0))
        self.assertIsNone(pwgen.generate_password(-1))
        self.assertIsNotNone(pwgen.generate_password(1))
        self.assertIsNotNone(pwgen.generate_password(100))
        self.assertIsNone(pwgen.generate_password("a"))

unittest.main()