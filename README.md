# Password Strength Checker

A Python command-line application that evaluates password characteristics using security policy checks, estimated entropy, and a compromised-password database lookup.

## Features

- Validates minimum password length (12 characters)
- Checks uppercase and lowercase letters
- Checks for digits and special characters
- Estimates password entropy in bits
- Classifies password strength as Weak, Moderate, Strong, or Exceptional
- Provides actionable improvement suggestions
- Checks passwords against the Have I Been Pwned Pwned Passwords database
- Uses a privacy-conscious range API lookup rather than sending the complete password to the API
- Handles unavailable network lookups without treating them as confirmed safe results

## Technologies

- Python 3
- `hashlib`
- `math`
- `string`
- `urllib`

## How It Works

The program evaluates a password against five basic policy criteria and estimates entropy based on the character types present.

For compromised-password detection, it calculates a SHA-1 hash locally and uses the first five hexadecimal characters to query the Pwned Passwords range API. It compares the remaining hash suffix locally. The complete password is not sent to the API.

The program then classifies password strength and provides recommendations based on the results.

## Testing

The following tests were performed using fictional test inputs:

- **Mixed-character test:** All five policy checks passed, and the program returned an Exceptional rating.
- **Short-password test (`abc`):** The program identified failed policy checks, returned a Weak rating, and detected a match in the compromised-password database.
- **Live API test:** The database lookup succeeded on the local computer.

These tests demonstrate the expected behaviour for the tested inputs; they do not constitute a formal security audit.

## Limitations

- Entropy is an estimate and assumes randomly selected characters.
- A database non-match does not guarantee that a password is secure.
- The live database lookup requires internet access.
- Network restrictions may prevent the database lookup from completing.
- Strength categories are educational classifications, not a formal security certification.

## How to Run

1. Install Python 3.
2. Download or clone this repository.
3. Open a terminal in the project folder.
4. Run:

   `python password_checker.py`

5. Enter a fictional test password when prompted.

## Security Note

Never enter real account passwords into a demonstration program or use real passwords for testing. Use a unique password or passphrase for each account.

## Project Status

Core functionality has been implemented and tested locally, including policy validation, entropy estimation, strength classification, recommendations, and the live compromised-password lookup.
