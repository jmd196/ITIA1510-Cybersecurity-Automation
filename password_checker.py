# This collects the name of the account or system the password is for (e.g., "Email", "SSH server", "VPN")
## account is the variable, = assigns a value, input() is the function, and "Enter Account Name: " is the argument.
account = input("Enter Account Name: ")

# This collects the username of the account or system. -- (Not used until Week 02.)
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

# This is the raw numeric strength indicator -- (Not used for classification until Week 02.)
## length_score is the variable, = assigns a value, * is the multiplication operator, password_length is the value being multiplied, and 10 is the integer it is multiplied by.
length_score = password_length * 10

# This uses floor division because only complete password rotations during the 36-month period should be counted.
## rotation_count is the variable, = assigns a value, // is the floor division operator, 36 is the number of months in 3 years, and rotation_interval is the number it is divided by.
rotation_count = 36 // rotation_interval

## This displays the completed password audit report using the information and calculations from above.
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
print("NOTE: Classification requires conditionals -- coming in Week 02.")
print("========================================")