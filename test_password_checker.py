# This imports the four check functions from password_checker.py so they can be tested without running the full interactive program.
## from tells Python which file/module to import from, import brings in the named functions, and the function names must match password_checker.py exactly.
from password_checker import check_length, check_digit, check_username, check_rotation


# This tests check_length() with a password that is too short.
## check_length() returns two values, so length_ok stores the Boolean result and length_verdict stores the classification string.
length_ok, length_verdict = check_length("test")
assert length_ok == False
print("PASS: check_length correctly returned False for a 4-character password")

# This tests check_length() with a password that is long enough to pass.
## This password has 16 characters, so length_ok should return True.
length_ok, length_verdict = check_length("abcdefghijklmnop")
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


# This tests check_rotation() with an interval that is more than 12 months.
## check_rotation() returns two values, so rotation_ok stores the Boolean result and rotation_verdict stores the classification string.
rotation_ok, rotation_verdict = check_rotation(18)
assert rotation_ok == False
print("PASS: check_rotation correctly returned False for an 18-month interval")

# This tests check_rotation() with an interval that is within the allowed range.
## A 6-month interval should make rotation_ok True.
rotation_ok, rotation_verdict = check_rotation(6)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for a 6-month interval")


# If the program reaches this line, all eight assert statements passed without an AssertionError.
print("All 8 tests passed.")