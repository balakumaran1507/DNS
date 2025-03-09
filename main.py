import socket
import struct

def build_dns_query(domain):
    """Build a raw DNS query for a given domain."""
    transaction_id = b'\xaa\xbb'  # Random ID
    flags = b'\x01\x00'  # Standard query
    questions = b'\x00\x01'  # One question
    answer_rrs = b'\x00\x00'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'
    
    # Encode domain to DNS format
    qname = b''.join(bytes([len(part)]) + part.encode() for part in domain.split('.')) + b'\x00'
    qtype = b'\x00\x01'  # A record (IPv4)
    qclass = b'\x00\x01'  # Internet class
    
    dns_query = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + qname + qtype + qclass
    return dns_query

def send_dns_query(domain, dns_server="8.8.8.8", port=53):
    """Sends a manual DNS query and retrieves the response."""
    query = build_dns_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    
    try:
        sock.sendto(query, (dns_server, port))
        response, _ = sock.recvfrom(512)  # Receive response (max 512 bytes)
        return response
    except socket.timeout:
        print("Request timed out.")
        return None
    finally:
        sock.close()

def parse_dns_response(response):
    """Parses the DNS response to extract the resolved IP address."""
    if not response:
        return None
    
    header = response[:12]
    qname_end = response.find(b'\x00', 12) + 5
    answer_section = response[qname_end:]
    
    if len(answer_section) < 16:
        print("No valid answer found.")
        return None
    print(answer_section)
    ip_bytes = answer_section[-4:]  # Last 4 bytes contain the IP
    resolved_ip = ".".join(map(str, ip_bytes))
    
    return resolved_ip

# Test the script
domain = input("Enter a domain (e.g., example.com): ")
response = send_dns_query(domain)

if response:
    ip = parse_dns_response(response)
    if ip:
        print(f"Resolved IP for {domain}: {ip}")
    else:
        print("Could not extract IP from response.")
