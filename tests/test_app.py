import unittest
from io import StringIO
import sys, os, contextlib
import subprocess


# Get the current directory of the helper.py module
current_dir = os.path.dirname(os.path.abspath(__file__))

# Get the path to the parent directory (project)
parent_dir = os.path.dirname(current_dir)

# Get the path to the main directory
main_dir = os.path.join(parent_dir, "src")

# Add the main directory to the sys.path list
sys.path.append(main_dir)

from applications import *

class ApplicationTestCase(unittest.TestCase):
    def test_sum_of_list_vul(self):
        i_vul = "__import__('os').system('echo YOU HAVE BEEN HACKED !!! ')"
        
        result = boschcoderace_sum_of_list_number(i_vul)
        self.assertFalse(result)


    def test_sum_of_list(self):
        i_lst = "[0, 10, 20, 30]"
        
        # Capture the printed output
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Call the function with the hacked input
        boschcoderace_sum_of_list_number(i_lst)
        
        # Get the printed output
        printed_output = captured_output.getvalue()
        
        # Assert that the hacked message is present in the printed output
        self.assertEqual("Sum of " + i_lst + " = 60\n", printed_output)
        
    def test_valid_ip(self):
        ip = "192.168.0.1"
        self.assertEqual(boschcoderace_validate_ip(ip), ip)

    def test_invalid_ip(self):
        ip = "256.0.0.1"
        self.assertRaises(ValueError, boschcoderace_validate_ip, ip)

        ip = "-c 10 192.168.0"
        self.assertRaises(ValueError, boschcoderace_validate_ip, ip)
    
    def test_set_permissions(self):
        path = "set_per_folder"
        result = boschcoderace_request_access(path)
        self.assertTrue(result)

    def test_file_not_found(self):
        path = "/nonexistent/file"
        self.assertRaises(ValueError, boschcoderace_request_access, path)

    def test_permission_denied(self):
        path = "/root/bin"
        self.assertRaises(ValueError, boschcoderace_request_access, path)

    def test_general_error(self):
        path = "/path/to/file"
        self.assertRaises(ValueError, boschcoderace_request_access, path)

    def test_valid_username(self):
        username = "john123"
        result = boschcoderace_check_username(username)
        self.assertTrue(result)

    def test_no_letter_username(self):
        username = "123456"
        result = boschcoderace_check_username(username)
        self.assertFalse(result)

    def test_no_digit_username(self):
        username = "abcdef"
        result = boschcoderace_check_username(username)
        self.assertTrue(result)

    def test_special_character_username(self):
        username = "user@name"
        result = boschcoderace_check_username(username)
        self.assertFalse(result)
        
    def test_matching_passwords(self):
        actual_pw = "password"
        typed_pw = "password"
        result = boschcoderace_validate_password(actual_pw, typed_pw)
        self.assertTrue(result)

    def test_non_matching_passwords(self):
        actual_pw = "password"
        typed_pw = "passw0rd"
        result = boschcoderace_validate_password(actual_pw, typed_pw)
        self.assertFalse(result)

    def test_different_lengths(self):
        actual_pw = "password"
        typed_pw = "pass"
        result = boschcoderace_validate_password(actual_pw, typed_pw)
        self.assertFalse(result)
    
    def test_different_random(self):
        salt = boschcoderace_random()
        self.assertIsInstance(salt, bytes)
        self.assertTrue(salt.startswith(b"$2b$12$"))
        self.assertEqual(len(salt), 29)

if __name__ == '__main__':
    unittest.main()