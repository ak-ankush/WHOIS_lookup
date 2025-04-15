# WHOIS_lookup
A Python script that provides detailed WHOIS information about a domain name(without https) or IP address. The script intelligently detects the input (domain or IP), fetches relevant registration or ownership information, and displays both sets of data in a clear, separate format without using any kind of external APIs.

### Features:
1. Domain WHOIS Lookup: Get domain registration info (registrar, creation/expiration dates, and ownership info).
2. IP WHOIS Lookup: Get IP ownership details (ISP, country, subnet, etc.).
3. Auto Resolves Domain to IP and viceversa: Automatically converts IP to domain (reverse DNS) or domain to IP.
4. Handles Missing Data Gracefully: Displays 'N/A' for redacted or missing WHOIS fields.

### Detailed Explanation
When you run the script, it asks you to enter either a domain name (google.com) or an IP address (142.251.40.206).

1. Input Handling:
- Checks if the input is a valid domain or IP address.
- Resolves the corresponding IP or domain.

2. Domain WHOIS Lookup:
- Uses the whois Python library to fetch registration details like Domain name, Registrar, Registration date, Expiration date, Last updated date, Owner name, organization, email, phone, address

3. IP WHOIS Lookup:
- Uses ipwhois library to gather like IP range/subnet, Hosting provider/ISP name, Network name, Country of registration

4. Output:
- Data is printed in two clearly separated sections
  -  Domain Registration Information
  -  IP Address Ownership Details

5. Output Example:

![image](https://github.com/user-attachments/assets/1088bf40-2371-4494-b92a-ad03f19b7169)

### Installation:
1. Clone the repo or download the script
2. Install required packages: pip install -r requirements.txt
3. Run the script: python whois_lookup.py
