
import math
import string
import hashlib
import urllib.request
import urllib.error


def check_compromised(password):
    """Check a password against the Pwned Passwords database."""
    password_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = password_hash[:5]
    suffix = password_hash[5:]

    url = "https://api.pwnedpasswords.com/range/" + prefix
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PasswordStrengthChecker/1.0",
            "Add-Padding": "true"
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 200:
                return None, 0
            data = response.read().decode("utf-8")

        for line in data.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                return True, int(parts[1])

        return False, 0

    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print("Lookup error:", repr(error))
        return None, 0


def calculate_entropy(password):
    """Estimate entropy assuming random character selection."""
    pool = 0

    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)

    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


def main():
    print("=" * 42)
    print("       PASSWORD STRENGTH CHECKER")
    print("=" * 42)
    print("Use a fake test password, never a real one.")

    password = input("\nEnter test password: ")

    if not password:
        print("Error: Password cannot be empty.")
        return

    # 1. Policy validation
    checks = {
        "At least 12 characters": len(password) >= 12,
        "Contains uppercase letters": any(c.isupper() for c in password),
        "Contains lowercase letters": any(c.islower() for c in password),
        "Contains digits": any(c.isdigit() for c in password),
        "Contains special characters": any(
            c in string.punctuation for c in password
        )
    }

    print("\n--- PASSWORD POLICY ---")
    for rule, passed in checks.items():
        print(("PASS" if passed else "FAIL") + ": " + rule)

    # 2. Entropy estimate
    entropy = calculate_entropy(password)

    print("\n--- ENTROPY ESTIMATE ---")
    print("Estimated entropy:", round(entropy, 2), "bits")
    print("Estimate assumes randomly selected characters.")

    # 3. Compromised-password database check
    print("\n--- COMPROMISED PASSWORD CHECK ---")
    compromised, occurrences = check_compromised(password)

    if compromised is True:
        print("WARNING: Password found in the breach database.")
        print("Reported occurrences:", occurrences)
    elif compromised is False:
        print("No match found in the queried database.")
    else:
        print("Lookup unavailable. Result is inconclusive.")

    # 4. Strength classification
    passed_count = sum(checks.values())

    if compromised is True or passed_count <= 2 or entropy < 40:
        strength = "Weak"
    elif passed_count <= 3 or entropy < 60:
        strength = "Moderate"
    elif passed_count == 4 or entropy < 80:
        strength = "Strong"
    else:
        strength = "Exceptional"

    print("\n--- STRENGTH ASSESSMENT ---")
    print("Strength rating:", strength)

    # 5. Actionable feedback
    print("\n--- RECOMMENDATIONS ---")

    failed_checks = [
        rule for rule, passed in checks.items() if not passed
    ]

    for rule in failed_checks:
        print("- Improve: " + rule)

    if not failed_checks:
        print("- All basic policy checks passed.")

    if compromised is True:
        print("- Replace this password with a unique one.")
        print("- Never reuse a password found in a breach.")
    elif compromised is None:
        print("- Retry the database lookup when network access works.")

    if len(password) < 16:
        print("- Consider using a longer password or passphrase.")

    print("\nImportant:")
    print("- Entropy is an estimate, not a security guarantee.")
    print("- A database non-match does not guarantee safety.")
    print("- The complete password is not sent to the API.")


if __name__ == "__main__":
    main()
