import socket
import whois
from ipwhois import IPWhois
import validators
import re


def is_ip(address):
    """Check if the address is a valid IP address (IPv4 or IPv6)."""
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False


def get_domain_from_ip(ip):
    """Get the domain name associated with an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def get_ip_from_domain(domain):
    """Get the IP address associated with a domain."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def whois_domain_info(domain):
    """Fetch WHOIS domain registration and ownership details."""
    try:
        w = whois.whois(domain)
        domain_info = {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Registration Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Last Updated Date": w.updated_date,
            "Registrant Name": w.get('name'),
            "Registrant Organization": w.get('org'),
            "Registrant Email": w.get('emails'),
            "Registrant Phone": w.get('phone'),
            "Registrant Address": w.get('address')
        }
        return domain_info
    except Exception as e:
        return {"Error": f"Error fetching WHOIS info: {str(e)}"}


def whois_ip_info(ip):
    """Fetch WHOIS information for an IP address."""
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        ip_info = {
            "IP Address": ip,
            "Network Name": res['network']['name'],
            "Country": res['network'].get('country', 'N/A'),
            "CIDR Subnet Range": res['network']['cidr'],
            "ISP / Org": ', '.join([remark['description'] for remark in res['network']['remarks']])
        }
        return ip_info
    except Exception as e:
        return {"Error": f"Error fetching IP WHOIS info: {str(e)}"}


def display_details(domain_info, ip_info):
    """Display both domain and IP details together."""
    print("\n========== Domain Registration Information ==========")
    for key, value in domain_info.items():
        print(f"{key} : {value}")
    
    print("\n========== IP Address Ownership Details ==========")
    for key, value in ip_info.items():
        print(f"{key} : {value}")


def main():
    user_input = input("Enter a domain or IP address: ").strip()

    if is_ip(user_input):
        # If the input is an IP address, get domain details and IP details.
        ip = user_input
        domain = get_domain_from_ip(ip)
        domain_info = whois_domain_info(domain if domain else '')
        ip_info = whois_ip_info(ip)
        print(f"\nResolved Domain (if any): {domain if domain else 'N/A'}")
        display_details(domain_info, ip_info)
    
    elif validators.domain(user_input):
        # If the input is a domain name, get domain details and IP details.
        domain = user_input
        ip = get_ip_from_domain(domain)
        domain_info = whois_domain_info(domain)
        ip_info = whois_ip_info(ip)
        print(f"\nResolved IP Address: {ip if ip else 'N/A'}")
        display_details(domain_info, ip_info)
    
    else:
        print("Invalid input. Please enter a valid domain name or IP address.")


if __name__ == "__main__":
    main()
