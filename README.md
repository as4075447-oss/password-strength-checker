
# Password Strength Checker

A Python project that evaluates password characteristics using
security policy checks and an estimated entropy calculation.

## Features

- Checks minimum password length
- Checks uppercase and lowercase letters
- Checks for digits and special characters
- Estimates password entropy in bits
- Classifies password strength
- Provides actionable improvement suggestions
- Attempts to check passwords against the
  Have I Been Pwned Pwned Passwords database

## Technologies

- Python 3
- hashlib
- math
- string
- urllib

## How It Works

The program evaluates the password against five basic policy
criteria and estimates entropy based on the character types
present.

It also attempts a privacy-conscious compromised-password
lookup. The complete password is not sent to the API.

## Limitations

- Entropy is an estimate and assumes randomly selected characters.
- A database non-match does not guarantee a password is secure.
- The live database lookup requires internet access.
- Some browser-based Python environments block outgoing requests.
- The strength categories are educational classifications,
  not a formal security certification.

## Testing

Test with fictional passwords that represent different cases:

- A short password
- A password without digits
- A password containing multiple character types
- An empty input
- A database lookup when network access is available

Never use real account passwords for testing.

## Project Status

The basic policy checks and entropy calculation have been
tested in a browser-based Python editor. The live compromised-
password lookup still requires successful network testing.
