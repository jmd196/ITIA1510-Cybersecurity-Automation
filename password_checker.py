# This list contains known compromised passwords that will be checked during each password audit.
## It is defined outside the if __name__ == "__main__": block so the functions and test file can both use it.
known_breached = ["password", "password123", "123456", "qwerty", "letmein",
                  "welcome", "monkey", "dragon", "master", "sunshine"]


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


def check_breach(password, known_breached):
    """Checks whether a password is not in the known breached password list. Takes a password and the breach list. Returns not_breached as a Boolean."""

    # in can check the whole list for a matching value without manually walking through every item with a for loop.
    ## not in makes not_breached True when password does not appear anywhere in known_breached.
    not_breached = password not in known_breached

    # return sends the True or False result back to whatever part of the program called check_breach().
    return not_breached


def audit_password(account, username, password, rotation_interval, known_breached):
    """Audits one password and prints its report. Takes account, username, password, rotation_interval, and known_breached. Returns (passed, failed, critical)."""

    # These function calls run each individual password check and store the returned results.
    ## Each function handles one specific responsibility instead of putting all of the checking logic in one large block of code.
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    not_breached = check_breach(password, known_breached)

    # This finds the number of characters in the password. It is still needed for the same report output used in Week 03.
    ## len() returns the number of characters in password and stores it in password_length.
    password_length = len(password)

    # This is the raw numeric strength indicator for the password based on its length. The longer the password, the higher the score.
    ## length_score is the variable, = assigns a value, * is the multiplication operator, password_length is the value being multiplied, and 10 is the integer it is multiplied by.
    length_score = password_length * 10

    # This uses floor division because only complete password rotations during the 36-month period should be counted.
    ## rotation_count is the variable, = assigns a value, // is the floor division operator, 36 is the number of months in 3 years, and rotation_interval is the number it is divided by.
    rotation_count = 36 // rotation_interval

    # This checks whether the password passes all four requirements used for the overall verdict.
    ## length_ok, has_digit, not_username, and not_breached must all be True for overall_pass to be True.
    overall_pass = length_ok and has_digit and not_username and not_breached

    # These counters represent the result of this one password audit.
    ## They start at 0, and audit_password() will return either a pass or fail value and possibly a critical value to the main loop.
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

    # This displays whether the password was found in the known breached password list.
    ## A breached password is a critical finding even if the username does not match it.
    if not_breached:
        print("Breach check:       PASS — password not found in known breach list")
    else:
        print("Breach check:       CRITICAL — password found in known breach list")

    # This counts the account as critical once if either critical condition is found.
    ## or is used because a username match or a breached password is enough to make critical True for this audit.
    if not_username == False or not_breached == False:
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

    # return sends this password's pass, fail, and critical results back to the main loop.
    ## Returning these values allows the main loop to update the totals without the function changing the batch counters directly.
    return passed, failed, critical


# This check makes sure the main part of the program only runs when password_checker.py is run directly.
## When test_password_checker.py imports these functions, __name__ will not equal "__main__", so the credential list and reports will not run during the tests.
if __name__ == "__main__":

    # Each inner list is one credential record in this order: account, username, password, and rotation interval.
    ## The professor supplied these five records so the program produces both passing and failing examples.
    credentials = [
        ["Gmail", "jsmith", "password123", 12],
        ["SSH Server", "jsmith", "jsmith", 24],
        ["VPN", "jsmith", "Tr0ub4dor&3correct", 3],
        ["Company Email", "jsmith", "Summer2024!", 6],
        ["GitHub", "jsmith", "Blue-Harbor-72-Lantern", 6],
    ]

    # These counters keep track of the totals for all credential records.
    total_pass = 0
    total_fail = 0
    critical_count = 0
    count = 0

    # These lists store the account names that fail or receive a critical finding.
    ## append() will add an account name to the end of the correct list as each credential is audited.
    failed_accounts = []
    critical_accounts = []

    # This for loop walks through the credentials list one record at a time.
    ## Unlike using in to only check whether a value exists in a list, this for loop visits each record so the program can process all of its values.
    for credential in credentials:

        # These lines use indexes to take the four values from the current credential record and store them in named variables.
        account = credential[0]
        username = credential[1]
        password = credential[2]
        rotation_interval = credential[3]

        # This displays the report header for the current credential.
        ## count + 1 is used because count begins at 0, but the reports should be numbered starting with 1.
        print("========================================")
        print(" PASSWORD AUDIT REPORT (" + str(count + 1) + " of " + str(len(credentials)) + ")")
        print("========================================")

        # This calls audit_password() to run all of the checks and print the rest of the report.
        ## The three returned values are stored in passed, failed, and critical for this credential.
        passed, failed, critical = audit_password(account, username, password, rotation_interval, known_breached)

        # These lines add the returned results from this credential to the batch totals.
        total_pass = total_pass + passed
        total_fail = total_fail + failed
        critical_count = critical_count + critical

        # If this credential failed, append() adds its account name to failed_accounts.
        if failed == 1:
            failed_accounts.append(account)

        # If this credential had a critical finding, append() adds its account name to critical_accounts.
        if critical == 1:
            critical_accounts.append(account)

        # This adds one to count after the current credential audit is finished.
        count = count + 1

    # These strings are built from the account lists so the names can be printed on one line without using later string methods.
    failed_accounts_text = ""
    for index in range(len(failed_accounts)):
        if index > 0:
            failed_accounts_text = failed_accounts_text + ", "
        failed_accounts_text = failed_accounts_text + failed_accounts[index]

    critical_accounts_text = ""
    for index in range(len(critical_accounts)):
        if index > 0:
            critical_accounts_text = critical_accounts_text + ", "
        critical_accounts_text = critical_accounts_text + critical_accounts[index]

    # This section runs after all credential records have been checked and displays totals for the entire batch.
    print("========================================")
    print(" BATCH AUDIT SUMMARY")
    print("========================================")
    print("Credentials audited: " + str(count))
    print("Passed:              " + str(total_pass))
    print("Failed:              " + str(total_fail))
    print("----------------------------------------")
    print("Failed accounts:     " + failed_accounts_text)
    print("Critical flags:      " + str(critical_count))
    print("Critical accounts:   " + critical_accounts_text)
    print()
    print("NOTE: Breach list and credentials are hardcoded -- file reading coming in Week 08.")
    print("========================================")
    