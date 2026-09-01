# This collects the name of the account or system the password is for (e.g., "Email", "SSH server", "VPN")
## account is the variable, = assigns a value, input() is the function, and "Enter Account Name: " is the argument.
account = input("Enter Account Name: ")

# This collects the username of the account or system.
## username is the variable, = assigns a value, input() is the function, and "Enter Username: " is the argument.
username = input("Enter Username: ")

# This collects the password of the account or system.
## password is the variable, = assigns a value, input() is the function, and "Enter Password: " is the argument.
password = input("Enter Password: ")

# This collects how often the password will be changed using units of months.
## rotation_interval is the variable, = assigns a value, input() is the function, and "Enter Password Rotation Interval (Months): " is the argument.
rotation_interval = input("Enter Password Rotation Interval (Months): ")

# The rotation_interval returns a string, so it is converted here to an integer before being used in calculations.
## rotation_interval is the variable, = assigns a value, int() is the function, and rotation_interval inside the parentheses is the argument being converted to an integer.
rotation_interval = int(rotation_interval)

# This finds the number of characters in the password, len() is used to calculate the length of the password. That is used to create a score.
## password_length is the variable, = assigns a value, len() is the function, and password is the argument. len() returns the number of characters in the password.
password_length = len(password)

# This is the raw numeric strength indicator for the password based on its length. The longer the password, the higher the score.
## length_score is the variable, = assigns a value, * is the multiplication operator, password_length is the value being multiplied, and 10 is the integer it is multiplied by.
length_score = password_length * 10

# This uses floor division because only complete password rotations during the 36-month period should be counted.
## rotation_count is the variable, = assigns a value, // is the floor division operator, 36 is the number of months in 3 years, and rotation_interval is the number it is divided by.
rotation_count = 36 // rotation_interval


# This classifies the password based on the number of characters in the password.
## if checks the first condition, elif checks another condition if the previous one was false, and else handles anything that did not match the earlier conditions.
if password_length < 8:
    length_verdict = "WEAK — does not meet minimum length requirements"
elif password_length <= 11:
    length_verdict = "MODERATE — meets minimum but falls short of NIST recommendations"
elif password_length <= 14:
    length_verdict = "GOOD — acceptable length for most systems"
else:
    length_verdict = "STRONG — meets NIST SP 800-63B recommendations"

# This checks whether the password contains at least one number from 0 through 9.
## in checks whether a digit is inside the password, and or allows any one of the digit checks to make has_digit True.
has_digit = "0" in password or "1" in password or "2" in password or "3" in password or "4" in password or "5" in password or "6" in password or "7" in password or "8" in password or "9" in password

# This checks that the password and username are not the same.
## != means not equal. If the password and username are different, not_username will be True.
not_username = password != username

# This classifies how often the password is changed based on the rotation interval.
## if checks for more than 12 months, elif handles the remaining values that are 6 months or more, and else handles anything below 6 months.
if rotation_interval > 12:
    rotation_verdict = "WARNING — rotation interval exceeds recommended maximum of 12 months"
elif rotation_interval >= 6:
    rotation_verdict = "ACCEPTABLE — rotation interval within recommended range"
else:
    rotation_verdict = "EXCELLENT — frequent rotation policy detected"

# This checks whether the password passes all three requirements used for the overall verdict.
## length_ok, has_digit, and not_username must all be True for overall_pass to be True. and is used because all three conditions must pass.
length_ok = password_length >= 15
overall_pass = length_ok and has_digit and not_username


print("========================================")
print(" PASSWORD AUDIT REPORT")
print("========================================")
print("Account:           " + account)
print("Username:          " + username)
print("Password length:   " + str(password_length) + " characters")
print("Length score:      " + str(length_score) + " points")
print("Rotation interval: " + str(rotation_interval) + " months")
print("Rotations (3 yr):  " + str(rotation_count))
print("----------------------------------------")
print("Length verdict:    " + length_verdict)

if has_digit:
    print("Digit found:        YES")
else:
    print("Digit found:        NO")

if not_username:
    print("Username match:     NO")
else:
    print("Username match:     YES")
    print("CRITICAL — password must not match username.")

print("Rotation verdict:  " + rotation_verdict)
print("----------------------------------------")

if overall_pass:
    print("OVERALL: PASS — password meets all checked criteria")
else:
    print("OVERALL: FAIL — see findings above")

print("========================================")