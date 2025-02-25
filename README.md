# Security Header Checker

This script helps you audit security headers of websites to ensure they follow best practices as recommended by OWASP (Open Web Application Security Project). It checks for missing, misconfigured, and deprecated headers, and outputs the results in a detailed text file.

## Requirements

Before running the script, make sure you have the following Python libraries installed:

- `requests`
- `colorama`

You can install them using `pip`:

```
pip install requests colorama
```
## Description
The script checks the following security headers for each URL:
 - **Strict-Transport-Security**: Enforces HTTPS and protects against SSL stripping attacks.
 - **Content-Security-Policy**: Defines approved sources of content to prevent XSS and injection attacks.
 - **X-Content-Type-Options**: Prevents MIME sniffing.
 - **X-Frame-Options**: Controls whether the browser should allow framing to prevent clickjacking.
 - **Referrer-Policy**: Regulates the amount of referrer information sent with requests.

The script will
 - Identify missing headers.
 - Flag misconfigured headers.
 - Check for deprecated headers (such as X-XSS-Protection).

## Usage
```
git clone https://github.com/booksy-security/Security-Header-Check.git
cd security-header-checker
python secheadercheck.py
```
## Choose Input Method
When you run the script, you'll be prompted to choose an input method for the URLs you want to check:
 **please use option 2 and put urls in a host file. Option 1 is not working**
 1. Enter a list of URLs separated by commas.
 2. Provide a file containing a list of hosts (one per line).

**Option 1: Enter URLs directly**
You can enter multiple URLs separated by commas like this:
```
https://example.com, https://test.com, https://anotherexample.com
```

**Option 2: Provide a file with a list of URLs**
If you have a file containing a list of URLs (one per line), provide the file path when prompted.
For example, the file might look like this:
```
https://example.com
https://test.com
https://anotherexample.com
```
## Review the Results
Once the script completes its checks (Errors may appear), it will generate a results file called `Secheader_Check_results.txt`.
This file will contain detailed information on the following:
 - **Missing Recommended Headers**: Headers that are completely missing from the response.
 - **Misconfigured Recommended Headers**: Headers that are present but incorrectly configured.
 - **Deprecated Headers**: Headers that are deprecated (e.g., X-XSS-Protection).

This was build from of the back of blkphox secheaders project, I have just modified the output for ease of reporting  with the use of AI
https://github.com/blkph0x 
