import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from collections import defaultdict
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Define OWASP-recommended security headers and their descriptions
RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS and protects against SSL stripping attacks.",
        "required": True,
        "validate": lambda value: (
            "max-age" in value and
            "includeSubDomains" in value and
            int(value.split("max-age=")[1].split(";")[0]) >= 63072000
        ),
        "failure": "Strict-Transport-Security: max-age=63072000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "description": "Defines approved sources of content to prevent XSS and injection attacks.",
        "required": True,
        "validate": lambda value: "default-src" in value and "'unsafe-inline'" not in value and "*'" not in value,
        "failure": "Avoid 'unsafe-inline', wildcards (*), and ensure 'default-src' is defined."
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME sniffing.",
        "required": True,
        "validate": lambda value: value.lower() == "nosniff",
        "failure": "Set the value to 'nosniff'."
    },
    "X-Frame-Options": {
        "description": "Controls whether the browser should allow framing to prevent clickjacking.",
        "required": True,
        "validate": lambda value: value.lower() in ["deny", "sameorigin"],
        "failure": "Use 'DENY' or 'SAMEORIGIN'."
    },
    "Referrer-Policy": {
        "description": "Regulates the amount of referrer information sent with requests.",
        "required": True,
        "validate": lambda value: value.lower() in ["no-referrer", "strict-origin", "strict-origin-when-cross-origin"],
        "failure": "Use 'no-referrer', 'strict-origin', or 'strict-origin-when-cross-origin'."
    },
    "Permissions-Policy": {
        "description": "Manages access to browser features like geolocation and camera.",
        "required": True,
        "validate": lambda value: len(value.strip()) > 0,
        "failure": "Define policies to restrict access to browser features."
    },
}

# Define deprecated headers
DEPRECATED_HEADERS = {
    "X-XSS-Protection": "Deprecated. Set to '0' or remove entirely."
}

def format_section_title(title):
    line = "-" * len(title)
    return f"{Style.BRIGHT}{line}\n{title}\n{line}\n"

def check_security_headers(url):
    failed_items = defaultdict(lambda: defaultdict(list))  # Using defaultdict to avoid KeyError

    try:
        # Bypass SSL certificate validation
        response = requests.get(url, timeout=10, verify=False)  # 'verify=False' ignores SSL cert errors

        # Suppress SSL warnings when verify=False is used
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        headers = response.headers

        # Check recommended headers
        for header, config in RECOMMENDED_HEADERS.items():
            if header in headers:
                value = headers[header]
                if not config["validate"](value):
                    failed_items["Misconfigured Recommended Headers"][header].append(url)
            else:
                failed_items["Missing Recommended Headers"][header].append(url)

        # Check deprecated headers
        for header, recommendation in DEPRECATED_HEADERS.items():
            if header in headers:
                value = headers[header]
                failed_items["Deprecated Headers"][header].append(url)

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error: Unable to fetch the URL. Details: {e}")

    return failed_items

def main():
    print("Choose input method:")
    print("1. Enter a list of URLs separated by commas.")
    print("2. Provide a file containing a list of hosts (one per line).")

    choice = input("Enter your choice (1/2): ").strip()

    urls = []
    if choice == "1":
        input_urls = input("Enter URLs separated by commas (e.g., https://example.com,https://test.com): ")
        urls = [url.strip() for url in input_urls.split(",") if url.strip()]
    elif choice == "2":
        file_path = input("Enter the file path containing the list of hosts: ").strip()
        try:
            with open(file_path, "r") as file:
                urls = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File not found at {file_path}.")
            return
    else:
        print(f"{Fore.RED}Invalid choice. Please enter 1 or 2.")
        return

    # Dictionary to store results by type of failure (Missing, Misconfigured, Deprecated)
    all_failed_items = defaultdict(lambda: defaultdict(list))

    # Check headers for each URL
    for url in urls:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url  # Default to HTTPS if no scheme is provided
        failed_items = check_security_headers(url)
        
        # Update the overall failed items list
        for section, headers in failed_items.items():
            for header, failed_urls in headers.items():
                all_failed_items[section][header].extend(failed_urls)

    # Output the results to a file
    output_filename = "Secheader_Check_results.txt"
    with open(output_filename, "w") as file:
        # Write the section title
        file.write("\n" + format_section_title("Checking Security Headers") + "\n")

        # Output Missing Headers
        if "Missing Recommended Headers" in all_failed_items:
            file.write(format_section_title("Missing Recommended Headers"))
            for header, urls in all_failed_items["Missing Recommended Headers"].items():
                file.write(f"{Fore.RED}[-] {header} {RECOMMENDED_HEADERS.get(header, {}).get('failure', 'No recommendation available.')}\n")
                for url in urls:
                    file.write(f"    {url}\n")

        # Output Misconfigured Headers
        if "Misconfigured Recommended Headers" in all_failed_items:
            file.write(format_section_title("Misconfigured Recommended Headers"))
            for header, urls in all_failed_items["Misconfigured Recommended Headers"].items():
                file.write(f"{Fore.RED}[-] {header} {RECOMMENDED_HEADERS.get(header, {}).get('failure', 'No recommendation available.')}\n")
                for url in urls:
                    file.write(f"    {url}\n")

        # Output Deprecated Headers
        if "Deprecated Headers" in all_failed_items:
            file.write(format_section_title("Deprecated Headers"))
            for header, urls in all_failed_items["Deprecated Headers"].items():
                file.write(f"{Fore.RED}[-] {header} {DEPRECATED_HEADERS.get(header, 'No recommendation available.')}\n")
                for url in urls:
                    file.write(f"    {url}\n")

    print(f"Results have been saved to {output_filename}")

if __name__ == "__main__":
    main()
