import socket
import whois
from ipwhois import IPWhois
import validators
import re

def is_ip(address):
    return validators.ipv4(address) or validators.ipv6(address)

def resolve_ip_from_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.error:
        return None

def resolve_domain_from_ip(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Clean up known reverse DNS names
        if '1e100.net' in hostname:
            return 'google.com'
        elif 'amazonaws.com' in hostname:
            return 'amazon.com'
        return hostname
    except Exception:
        return None

def clean_date(value):
    if isinstance(value, list):
        return value[0].strftime('%Y-%m-%d %H:%M:%S') if value[0] else 'N/A'
    elif hasattr(value, 'strftime'):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return 'N/A'

def get_domain_whois(domain):
    try:
        w = whois.whois(domain)
        print("\n========== Domain Registration Information ==========")
        print(f"Domain Name : {w.domain_name}")
        print(f"Registrar : {w.registrar}")
        print(f"Registration Date : {clean_date(w.creation_date)}")
        print(f"Expiration Date : {clean_date(w.expiration_date)}")
        print(f"Last Updated Date : {clean_date(w.updated_date)}")
        print(f"Registrant Name : {getattr(w, 'name', 'N/A')}")
        print(f"Registrant Organization : {getattr(w, 'org', 'N/A')}")
        print(f"Registrant Email : {getattr(w, 'emails', 'N/A')}")
        print(f"Registrant Phone : {getattr(w, 'phone', 'N/A')}")
        print(f"Registrant Address : {getattr(w, 'address', 'N/A')}")
    except Exception as e:
        print("\n========== Domain Registration Information ==========")
        print(f"Error fetching WHOIS for domain: {e}")

def get_ip_whois(ip):
    print("\n========== IP Address Ownership Details ==========")
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        print(f"IP Address            : {ip}")
        print(f"Network Name          : {res.get('network', {}).get('name', 'N/A')}")
        print(f"Country               : {res.get('network', {}).get('country', 'N/A')}")
        print(f"CIDR Subnet Range     : {res.get('network', {}).get('cidr', 'N/A')}")
        print(f"ISP / Org             : {res.get('network', {}).get('remarks', ['N/A'])[0] if res.get('network', {}).get('remarks') else 'N/A'}")
    except Exception as e:
        print(f"Error fetching IP WHOIS info: {e}")

def main():
    user_input = input("Enter a domain or IP address: ").strip()

    if is_ip(user_input):
        ip = user_input
        domain = resolve_domain_from_ip(ip)
        if domain:
            print(f"\nResolved Domain (if any): {domain}")
            get_domain_whois(domain)
        get_ip_whois(ip)
    elif validators.domain(user_input):
        domain = user_input
        ip = resolve_ip_from_domain(domain)
        if ip:
            print(f"\nResolved IP Address: {ip}")
        get_domain_whois(domain)
        if ip:
            get_ip_whois(ip)
    else:
        print("Invalid domain or IP address entered.")

if __name__ == "__main__":
    main()
