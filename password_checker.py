import json
import os


# This dictionary stores the password policy rules in one place instead of putting the rule values inside the functions.
# It is outside the if __name__ == "__main__": block so the functions and the test file can both access it.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True,
    "history_runs": 3
}


def load_breached(filepath):
    """Read the breached password file. Returns a list of password strings."""
    known_breached = []

    # The with statement closes the file automatically when this block ends, even if an error stops the program.
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Blank lines are skipped so an empty string is not added to the breach list.
            if line != "":
                known_breached.append(line)

    return known_breached


def load_credentials(filepath):
    """Read the credential file. Returns a list of credential dictionaries."""
    credentials = []

    # The with statement closes the file automatically, so f.close() does not have to be called manually.
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Blank lines are skipped because they do not contain a credential record.
            if line == "":
                continue

            fields = line.split(",")

            # Each record uses the same four dictionary keys from Week 06.
            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3]),
            })

    return credentials


def write_report(report_lines, filepath):
    """Write each string in report_lines to the file as one line."""

    # Write mode replaces the old report instead of adding the new report to the end of it.
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")


def save_summary(summary, filepath):
    """Save the summary dictionary to a JSON file."""

    # Write mode replaces the old JSON file so it always contains the newest summary.
    with open(filepath, "w") as f:
        json.dump(summary, f, indent=2)


def load_summary(filepath):
    """Load and return a summary dictionary from a JSON file."""

    # json.load() changes the JSON object in the file back into a Python dictionary.
    with open(filepath, "r") as f:
        summary = json.load(f)

    return summary


def load_history(filepath):
    """Load and return the audit history list. Returns an empty list if the file does not exist."""

    # A missing history file means no audit runs have been saved yet, so an empty list lets the first run start the history.
    if os.path.exists(filepath) == False:
        return []

    # If the file already exists, json.load() changes the saved JSON array back into a Python list.
    with open(filepath, "r") as f:
        history = json.load(f)

    return history


def add_to_history(history, summary, keep):
    """Add the newest audit summary to history and keep only the newest entries."""

    # The newest saved run is history[-1]. Its run number is used instead of len(history) because trimming stops the list length from growing.
    if len(history) == 0:
        run = 1
    else:
        run = history[-1]["run"] + 1

    # Each history entry keeps the run number, pass/fail counts, and the list of accounts with critical findings.
    history.append({
        "run": run,
        "passed": summary["passed"],
        "failed": summary["failed"],
        "critical_accounts": summary["critical_accounts"]
    })

    # A negative slice keeps only the newest runs so the history does not grow without limit.
    return history[-keep:]


def save_history(history, filepath):
    """Save the audit history list to a JSON file."""

    # indent=2 makes the saved history easier for a person to read without changing the data.
    with open(filepath, "w") as f:
        json.dump(history, f, indent=2)


def check_length(password, policy):
    """Checks password length against the policy thresholds. Takes a password string and policy dictionary. Returns (length_ok, length_verdict)."""

    # This finds the number of characters in the password.
    ## password_length is the variable, = assigns a value, len() is the function, and password is the argument.
    password_length = len(password)

    # Reading the length limits from policy keeps the rule in one location instead of repeating the same number inside the function.
    ## If the policy changes later, the function can use the new limit without changing the comparison that reads that policy key.
    if password_length < policy["min_length"]:
        length_verdict = "WEAK — does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = "MODERATE — meets minimum but falls short of NIST recommendations"
    elif password_length < policy["strong_length"]:
        length_verdict = "GOOD — acceptable length for most systems"
    else:
        length_verdict = "STRONG — meets NIST SP 800-63B recommendations"

    # This checks whether the password meets the strong length requirement stored in policy.
    ## policy["strong_length"] looks up the value using the dictionary key instead of putting the strong-length number here.
    length_ok = password_length >= policy["strong_length"]

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


def check_rotation(rotation_interval, policy):
    """Checks the password rotation interval using the policy dictionary. Returns (rotation_ok, rotation_verdict)."""

    # Reading the rotation limit from policy is better than writing the number here because the rule only needs to be changed in one place.
    ## <= compares rotation_interval to the value stored under the "max_rotation_months" key.
    rotation_ok = rotation_interval <= policy["max_rotation_months"]

    # This classifies how often the password is changed using the rotation limits stored in policy.
    if rotation_interval > policy["max_rotation_months"]:
        rotation_verdict = "WARNING — rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= policy["good_rotation_months"]:
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


def audit_password(account, username, password, rotation_interval, known_breached, policy, report_lines):
    """Audits one password and adds its report to report_lines. Returns (passed, failed, critical)."""

    # These function calls run each individual password check and store the returned results.
    ## check_length() and check_rotation() receive policy because their rules are now stored in the policy dictionary.
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    not_breached = check_breach(password, known_breached)

    # This finds the number of characters in the password. It is still needed for the same report output used in previous weeks.
    ## len() returns the number of characters in password and stores it in password_length.
    password_length = len(password)

    # This is the raw numeric strength indicator for the password based on its length. The longer the password, the higher the score.
    ## length_score is the variable, = assigns a value, * is the multiplication operator, password_length is the value being multiplied, and 10 is the integer it is multiplied by.
    length_score = password_length * 10

    # This uses floor division because only complete password rotations during the 36-month period should be counted.
    ## rotation_count is the variable, = assigns a value, // is the floor division operator, 36 is the number of months in 3 years, and rotation_interval is the number it is divided by.
    rotation_count = 36 // rotation_interval

    # These variables determine whether the digit and breach checks are required by the policy.
    ## If a rule is turned off in policy, that rule will not cause the overall password check to fail.
    if policy["require_digit"]:
        digit_ok = has_digit
    else:
        digit_ok = True

    if policy["check_breach_list"]:
        breach_ok = not_breached
    else:
        breach_ok = True

    # This checks whether the password passes all of the requirements that are enabled by the policy.
    overall_pass = length_ok and digit_ok and not_username and breach_ok

    # These counters represent the result of this one password audit.
    passed = 0
    failed = 0
    critical = 0

    # These lines add the completed password audit report for the current password to report_lines.
    report_lines.append("Account:           " + account)
    report_lines.append("Username:          " + username)
    report_lines.append("Password length:   " + str(password_length) + " characters")
    report_lines.append("Length score:      " + str(length_score) + " points")
    report_lines.append("Rotation interval: " + str(rotation_interval) + " months")
    report_lines.append("Rotations (3 yr):  " + str(rotation_count))
    report_lines.append("----------------------------------------")
    report_lines.append("Length verdict:    " + length_verdict)

    # This adds whether a digit was found in the password to report_lines.
    if has_digit:
        report_lines.append("Digit found:        YES")
    else:
        report_lines.append("Digit found:        NO")

    # This adds whether the password matches the username to report_lines.
    if not_username:
        report_lines.append("Username match:     NO")
    else:
        report_lines.append("Username match:     YES")
        report_lines.append("CRITICAL — password must not match username.")

    # This adds the breach check result to report_lines.
    if not_breached:
        report_lines.append("Breach check:       PASS — password not found in known breach list")
    else:
        report_lines.append("Breach check:       CRITICAL — password found in known breach list")

    # This counts the account as critical once if either enabled critical condition is found.
    if not_username == False or (policy["check_breach_list"] and not_breached == False):
        critical = critical + 1

    # This adds the rotation classification to report_lines.
    report_lines.append("Rotation verdict:  " + rotation_verdict)
    report_lines.append("----------------------------------------")

    # This checks the final Boolean result and increases either the pass counter or the fail counter.
    if overall_pass:
        report_lines.append("OVERALL: PASS — password meets all checked criteria")
        passed = passed + 1
    else:
        report_lines.append("OVERALL: FAIL — see findings above")
        failed = failed + 1

    report_lines.append("========================================")
    report_lines.append("")

    # return sends this password's pass, fail, and critical results back to the main loop.
    return passed, failed, critical


# This check makes sure the main part of the program only runs when password_checker.py is run directly.
## The policy and functions above this block can be imported by test_password_checker.py without running the reports.
if __name__ == "__main__":

    # The credentials and breach list are loaded from text files so the data can change without changing the Python code.
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")
    report_lines = []

    # One summary dictionary now stores the totals and account lists that were previously stored in separate variables.
    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    # This for loop walks through each credential dictionary.
    ## cred stores one dictionary at a time, and its values are accessed by their key names instead of numbered indexes.
    for cred in credentials:

        # This adds the report header for the current credential to report_lines.
        report_lines.append("========================================")
        report_lines.append(" PASSWORD AUDIT REPORT (" + str(summary["total"] + 1) + " of " + str(len(credentials)) + ")")
        report_lines.append("========================================")

        # Dictionary keys make the record easier to understand because each value is read by name.
        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy,
            report_lines
        )

        # These dictionary keys keep the totals for all five credential records.
        ## += is used here because the professor specifically provides this form in the Week 06 instructions.
        summary["total"] += 1
        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        # If this credential failed, append() adds its account name to the failed_accounts list stored inside summary.
        if failed == 1:
            summary["failed_accounts"].append(cred["account"])

        # If this credential had a critical finding, append() adds its account name to the critical_accounts list stored inside summary.
        if critical == 1:
            summary["critical_accounts"].append(cred["account"])

    # These strings are built from the account lists so the names can still be printed on one line.
    failed_accounts_text = ""
    for index in range(len(summary["failed_accounts"])):
        if index > 0:
            failed_accounts_text = failed_accounts_text + ", "
        failed_accounts_text = failed_accounts_text + summary["failed_accounts"][index]

    critical_accounts_text = ""
    for index in range(len(summary["critical_accounts"])):
        if index > 0:
            critical_accounts_text = critical_accounts_text + ", "
        critical_accounts_text = critical_accounts_text + summary["critical_accounts"][index]

    # This section runs after all credential dictionaries have been checked and adds the batch totals to report_lines.
    # get() is used with a default for the total so a missing key would return 0 instead of causing a KeyError.
    report_lines.append("========================================")
    report_lines.append(" BATCH AUDIT SUMMARY")
    report_lines.append("========================================")
    report_lines.append("Credentials audited: " + str(summary.get("total", 0)))
    report_lines.append("Passed:              " + str(summary["passed"]))
    report_lines.append("Failed:              " + str(summary["failed"]))
    report_lines.append("----------------------------------------")
    report_lines.append("Failed accounts:     " + failed_accounts_text)
    report_lines.append("Critical flags:      " + str(summary["critical"]))
    report_lines.append("Critical accounts:   " + critical_accounts_text)
    report_lines.append("========================================")

    # The console and report.txt use the same report_lines list so their contents match.
    for line in report_lines:
        print(line)

    write_report(report_lines, "report.txt")
    save_summary(summary, "audit_summary.json")

    # The history is loaded after the current summary is saved, then this run is added and trimmed to the policy limit.
    history = load_history("audit_history.json")
    history = add_to_history(history, summary, policy["history_runs"])
    save_history(history, "audit_history.json")
