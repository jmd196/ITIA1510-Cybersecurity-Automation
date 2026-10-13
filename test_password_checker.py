# This imports the check functions, file functions, and policy dictionary from password_checker.py.
## Importing them allows the functions and policy rules to be tested without running the main program.
from password_checker import (check_length, check_digit, check_username, check_rotation,
                              check_breach, load_credentials, load_breached, write_report, policy)

# The breach list is now loaded from breached.txt instead of being stored inside password_checker.py.
known_breached = load_breached("breached.txt")


# This tests check_length() with a password that is too short.
## check_length() now also receives policy because its length rules are stored in the policy dictionary.
length_ok, length_verdict = check_length("test", policy)
assert length_ok == False
print("PASS: check_length correctly returned False for a 4-character password")

# This tests check_length() with a password that is long enough to pass.
## This password has 16 characters, which is longer than the strong_length value stored in policy.
length_ok, length_verdict = check_length("abcdefghijklmnop", policy)
assert length_ok == True
print("PASS: check_length correctly returned True for a 16-character password")


# This tests check_digit() with a password that does not contain any digits.
## check_digit() returns a Boolean value, so has_digit should be False here.
has_digit = check_digit("password")
assert has_digit == False
print("PASS: check_digit correctly returned False for a password with no digits")

# This tests check_digit() with a password that contains at least one digit.
## The number 1 is inside the password, so has_digit should be True.
has_digit = check_digit("password1")
assert has_digit == True
print("PASS: check_digit correctly returned True for a password containing a digit")


# This tests check_username() when the password and username are the same.
## Because the values match, not_username should be False.
not_username = check_username("jsmith", "jsmith")
assert not_username == False
print("PASS: check_username correctly returned False when the password matches the username")

# This tests check_username() when the password and username are different.
## Because the values do not match, not_username should be True.
not_username = check_username("StrongPassword1", "jsmith")
assert not_username == True
print("PASS: check_username correctly returned True when the password and username are different")


# This tests check_rotation() with an interval that is more than the maximum stored in policy.
## check_rotation() now receives policy because its rotation limits are stored in the policy dictionary.
rotation_ok, rotation_verdict = check_rotation(18, policy)
assert rotation_ok == False
print("PASS: check_rotation correctly returned False for an 18-month interval")

# This tests check_rotation() with an interval that is within the allowed range.
## A 6-month interval should make rotation_ok True.
rotation_ok, rotation_verdict = check_rotation(6, policy)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for a 6-month interval")


# This tests check_breach() with a password that appears in the known breached password list.
## Because "password123" is in known_breached, not_breached should be False.
not_breached = check_breach("password123", known_breached)
assert not_breached == False
print("PASS: check_breach correctly returned False for a known breached password")

# This tests check_breach() with a password that is not in the known breached password list.
## Because "Blue-Harbor-72-Lantern" is not in known_breached, not_breached should be True.
not_breached = check_breach("Blue-Harbor-72-Lantern", known_breached)
assert not_breached == True
print("PASS: check_breach correctly returned True for a password not in the known breach list")


# This tests that the policy dictionary contains the required strong password length.
## Dictionary values are accessed by their key, so "strong_length" should return 15.
assert policy["strong_length"] == 15
print("PASS: policy strong_length is set to 15")

# This tests that the policy dictionary contains the require_digit rule.
## in checks whether "require_digit" exists as a key in the policy dictionary.
assert "require_digit" in policy
print("PASS: policy contains the require_digit key")


# This tests that load_credentials() returns a list.
credentials = load_credentials("credentials.txt")
assert type(credentials) == list
print("PASS: load_credentials returned a list")

# This tests that the first credential dictionary contains the required account key.
assert "account" in credentials[0]
print("PASS: first credential contains the account key")


# This tests that load_breached() returns a list.
breached_passwords = load_breached("breached.txt")
assert type(breached_passwords) == list
print("PASS: load_breached returned a list")

# This tests that a known breached password was read from breached.txt.
assert "password123" in breached_passwords
print("PASS: load_breached read password123 from breached.txt")


# This tests that write_report() writes each list item as one line in the output file.
test_lines = ["first line", "second line"]
write_report(test_lines, "test_report.txt")

with open("test_report.txt", "r") as f:
    test_report_text = f.read()

assert test_report_text == "first line\nsecond line\n"
print("PASS: write_report wrote the expected text")


# If the program reaches this line, all seventeen assert statements passed without an AssertionError.
print("All 17 tests passed.")
