# This imports the check functions and the known breach list from password_checker.py so they can be tested without running the main program.
## from tells Python which file/module to import from, and import brings in the named functions and list.
from password_checker import check_length, check_digit, check_username, check_rotation, check_breach, known_breached


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


# If the program reaches this line, all ten assert statements passed without an AssertionError.
print("All 10 tests passed.")
