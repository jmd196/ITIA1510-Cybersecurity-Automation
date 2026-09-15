def check_length(password):
    """Checks password length against NIST SP 800-63B thresholds. Takes a password string. Returns (length_ok, length_verdict)."""

    # This finds the number of characters in the password, len() is used to calculate the length of the password.
    ## password_length is the variable, = assigns a value, len() is the function, and password is the argument. len() returns the number of characters in the password.
    password_length = len(password)

    # This classifies the password based on the number of characters in the password.
    ## if checks the first condition, elif checks another condition if the previous one was False, and else handles anything that did not match the earlier conditions.
    if password_length < 8:
        length_verdict = "WEAK — does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = "MODERATE — meets minimum but falls short of NIST recommendations"
    elif password_length <= 14:
        length_verdict = "GOOD — acceptable length for most systems"
    else:
        length_verdict = "STRONG — meets NIST SP 800-63B recommendations"

    # This checks whether the password meets the minimum length needed for the overall PASS verdict.
    ## length_ok is the variable, = assigns a value, >= means greater than or equal to, and 15 is the minimum required length.
    length_ok = password_length >= 15

    # return sends both results back to whatever part of the program called check_length().
    return length_ok, length_verdict


def check_digit(password):
    """Checks whether a password contains a digit. Takes a password string. Returns has_digit as a Boolean."""

    # This starts by assuming that no digit has been found in the password.
    ## has_digit is the variable, = assigns a value, and False is the Boolean value assigned before checking each character.
    has_digit = False

    # This checks each character in the password one at a time instead of writing a separate check for every possible digit like Week 02.
    ## for starts the loop, char temporarily stores each character, and in tells Python to go through the characters inside password one at a time.
    for char in password:

        # This checks whether the current character is one of the digits from 0 through 9.
        ## char is the current character being checked, and in tests whether it appears inside the string "0123456789".
        if char in "0123456789":

            # If a digit is found, has_digit changes from False to True.
            ## has_digit is the variable, = assigns a value, and True is the Boolean value being assigned.
            has_digit = True

    # return sends the final True or False value back to whatever part of the program called check_digit().
    return has_digit


def check_username(password, username):
    """Checks whether the password is different from the username. Takes password and username strings. Returns not_username as a Boolean."""

    # This checks that the password and username are not the same.
    ## != means not equal. If the password and username are different, not_username will be True.
    not_username = password != username

    # return sends the True or False result back to whatever part of the program called check_username().
    return not_username


def check_rotation(rotation_interval):
    """Checks the password rotation interval. Takes rotation_interval as an integer. Returns (rotation_ok, rotation_verdict)."""

    # This checks whether the rotation interval is 12 months or fewer.
    ## rotation_ok is the variable, = assigns a value, and <= means less than or equal to.
    rotation_ok = rotation_interval <= 12

    # This classifies how often the password is changed based on the rotation interval.
    ## if checks for more than 12 months, elif handles the remaining values that are 6 months or more, and else handles anything below 6 months.
    if rotation_interval > 12:
        rotation_verdict = "WARNING — rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE — rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT — frequent rotation policy detected"

    # return sends both results back to whatever part of the program called check_rotation().
    return rotation_ok, rotation_verdict


def audit_password(account, username, password, rotation_interval):
    """Audits one password and prints its report. Takes account, username, password, and rotation_interval. Returns (passed, failed, critical)."""

    # These function calls run each individual password check and store the returned results.
    ## Each function handles one specific responsibility instead of putting all of the checking logic in one large block of code.
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)

    # This finds the number of characters in the password. It is still needed for the same report output used in Week 03.
    ## len() returns the number of characters in password and stores it in password_length.
    password_length = len(password)

    # This is the raw numeric strength indicator for the password based on its length. The longer the password, the higher the score.
    ## length_score is the variable, = assigns a value, * is the multiplication operator, password_length is the value being multiplied, and 10 is the integer it is multiplied by.
    length_score = password_length * 10

    # This uses floor division because only complete password rotations during the 36-month period should be counted.
    ## rotation_count is the variable, = assigns a value, // is the floor division operator, 36 is the number of months in 3 years, and rotation_interval is the number it is divided by.
    rotation_count = 36 // rotation_interval

    # This checks whether the password passes all three requirements used for the overall verdict.
    ## length_ok, has_digit, and not_username must all be True for overall_pass to be True. and is used because all three conditions must pass.
    overall_pass = length_ok and has_digit and not_username

    # These counters represent the result of this one password audit.
    ## They start at 0, and audit_password() will return either a pass or fail value and possibly a critical value to the batch loop.
    passed = 0
    failed = 0
    critical = 0

    # This displays the completed password audit report for the current password.
    print("Account:           " + account)
    print("Username:          " + username)
    print("Password length:   " + str(password_length) + " characters")
    print("Length score:      " + str(length_score) + " points")
    print("Rotation interval: " + str(rotation_interval) + " months")
    print("Rotations (3 yr):  " + str(rotation_count))
    print("----------------------------------------")
    print("Length verdict:    " + length_verdict)

    # This displays whether a digit was found in the password.
    ## If has_digit is True it prints YES, otherwise the else block prints NO.
    if has_digit:
        print("Digit found:        YES")
    else:
        print("Digit found:        NO")

    # This displays whether the password matches the username.
    ## If not_username is True, the values are different. If it is False, they match and the critical warning is displayed.
    if not_username:
        print("Username match:     NO")
    else:
        print("Username match:     YES")
        print("CRITICAL — password must not match username.")

        # This adds one to the critical counter when the password matches its username.
        ## critical = critical + 1 takes the current value, adds 1, and stores the new value back into critical.
        critical = critical + 1

    # This displays the rotation classification that was calculated above.
    print("Rotation verdict:  " + rotation_verdict)
    print("----------------------------------------")

    # This checks the final Boolean result and increases either the pass counter or the fail counter.
    ## Only one of these counters increases for each password because overall_pass can only be True or False.
    if overall_pass:
        print("OVERALL: PASS — password meets all checked criteria")

        # This adds one to the number of passwords that passed.
        passed = passed + 1
    else:
        print("OVERALL: FAIL — see findings above")

        # This adds one to the number of passwords that failed.
        failed = failed + 1

    print("========================================")
    print()

    # return sends this password's pass, fail, and critical results back to the batch loop.
    ## Returning these values allows the batch loop to update the totals without the function changing the batch counters directly.
    return passed, failed, critical


# This check makes sure the interactive part of the program only runs when password_checker.py is run directly.
## When test_password_checker.py imports these functions, __name__ will not equal "__main__", so the input prompts and batch loop will not run during the tests.
if __name__ == "__main__":

    # This sets how many passwords will be checked during one run of the program.
    ## batch_size is the variable, = assigns a value, and 3 is the integer being assigned to the variable.
    batch_size = 3

    # This keeps track of how many passwords have already been checked. It starts at 0 because no passwords have been checked yet.
    ## count is the variable, = assigns a value, and 0 is the starting integer value.
    count = 0

    # These counters are created before the while loop so their totals are not reset each time the loop runs.
    ## Each variable starts at 0 and will increase when a password passes, fails, or causes a critical username-match warning.
    total_pass = 0
    total_fail = 0
    critical_count = 0

    # This while loop repeats the password audit until the number of completed audits reaches the batch size.
    ## while starts the loop, count < batch_size is the condition, and the loop continues as long as that condition is True.
    while count < batch_size:

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

        # This displays the report header for the current password.
        ## count + 1 is used because count begins at 0, but the reports should be numbered starting with 1.
        print("========================================")
        print(" PASSWORD AUDIT REPORT (" + str(count + 1) + " of " + str(batch_size) + ")")
        print("========================================")

        # This calls audit_password() to run all of the checks and print the rest of the report.
        ## The three returned values are stored in passed, failed, and critical for this password.
        passed, failed, critical = audit_password(account, username, password, rotation_interval)

        # These lines add the returned results from this password to the batch totals.
        ## The batch counters stay outside audit_password() so they keep their totals across all three passwords.
        total_pass = total_pass + passed
        total_fail = total_fail + failed
        critical_count = critical_count + critical

        # This adds one to count after the current password audit is finished.
        ## count = count + 1 takes the current count, adds 1, and stores the new value back into count.
        # Increasing count is important because eventually count will equal batch_size and the while loop will stop.
        count = count + 1

    # This section is outside the while loop, so it only runs after all passwords in the batch have been checked.
    # The counters kept their values during every loop, which allows this section to display totals for the entire batch.
    print("========================================")
    print(" BATCH AUDIT SUMMARY")
    print("========================================")
    print("Passwords audited: " + str(count))
    print("Passed:            " + str(total_pass))
    print("Failed:            " + str(total_fail))
    print("Critical flags:    " + str(critical_count))
    print("========================================")
    print("NOTE: Input is still hardcoded -- file reading coming in Week 08.")