import socket
import ssl
import argparse
import sys
import logging
import re
from contextlib import closing
import json
import warnings

# Suppress DeprecationWarning
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('sslscan.py')

def check_port(host, port, timeout=5):
    """Check if port is open"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return True
    except:
        return False

def check_tls_support(host, port):
    """Check TLS protocol support"""
    results = {}

    # Protocols to check
    protocols = [
        ('SSLv3', ssl.PROTOCOL_SSLv23),
        ('TLSv1.0', ssl.PROTOCOL_TLSv1),
        ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
        ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
        ('TLSv1.3', ssl.PROTOCOL_TLS),
    ]

    for proto_name, proto_const in protocols:
        try:
            # Create context for specific protocol
            context = ssl.SSLContext(proto_const)

            # For modern protocols, use flags to isolate version
            if proto_name in ['TLSv1.2', 'TLSv1.3']:
                if hasattr(ssl, "OP_NO_TLSv1_1"):
                    context.options |= ssl.OP_NO_TLSv1_1
                if hasattr(ssl, "OP_NO_TLSv1"):
                    context.options |= ssl.OP_NO_TLSv1
                if hasattr(ssl, "OP_NO_SSLv3"):
                    context.options |= ssl.OP_NO_SSLv3
                if hasattr(ssl, "OP_NO_SSLv2"):
                    context.options |= ssl.OP_NO_SSLv2

                if proto_name == 'TLSv1.2' and hasattr(ssl, "OP_NO_TLSv1_3"):
                    context.options |= ssl.OP_NO_TLSv1_3
                elif proto_name == 'TLSv1.3' and hasattr(ssl, "OP_NO_TLSv1_2"):
                    context.options |= ssl.OP_NO_TLSv1_2

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.do_handshake()
                    results[proto_name] = True
        except Exception as e:
            logger.debug(f"Protocol {proto_name} failed: {str(e)}")
            results[proto_name] = False

    # Always mark SSLv2 as unsupported
    results['SSLv2'] = False

    return results

def get_certificate_info(host, port):
    """Get certificate information"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_info = ssock.getpeercert()
                return cert_info
    except Exception as e:
        logger.error(f"Certificate error: {str(e)}")
        return None

def get_all_ciphers():
    """Return all ciphers to check"""
    return [
        # TLS 1.3 ciphers
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_CCM_SHA256',
        'TLS_AES_128_CCM_8_SHA256',

        # ECDHE ciphers
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-CHACHA20-POLY1305',
        'ECDHE-RSA-CHACHA20-POLY1305',
        'ECDHE-ECDSA-AES256-SHA384',
        'ECDHE-RSA-AES256-SHA384',
        'ECDHE-ECDSA-AES128-SHA256',
        'ECDHE-RSA-AES128-SHA256',
        'ECDHE-ECDSA-AES256-SHA',
        'ECDHE-RSA-AES256-SHA',
        'ECDHE-ECDSA-AES128-SHA',
        'ECDHE-RSA-AES128-SHA',

        # DHE ciphers
        'DHE-RSA-AES256-GCM-SHA384',
        'DHE-RSA-AES128-GCM-SHA256',
        'DHE-RSA-AES256-SHA256',
        'DHE-RSA-AES128-SHA256',
        'DHE-RSA-AES256-SHA',
        'DHE-RSA-AES128-SHA',
        'DHE-RSA-CHACHA20-POLY1305',

        # AES ciphers
        'AES256-GCM-SHA384',
        'AES128-GCM-SHA256',
        'AES256-SHA256',
        'AES128-SHA256',
        'AES256-SHA',
        'AES128-SHA',

        # Camellia ciphers
        'CAMELLIA256-SHA256',
        'CAMELLIA128-SHA256',
        'CAMELLIA256-SHA',
        'CAMELLIA128-SHA',

        # 3DES ciphers
        'DES-CBC3-SHA',

        # GOST ciphers
        'GOST2012-GOST8912-GOST8912',
        'GOST2001-GOST89-GOST89',
        'GOST94-GOST89-GOST89',

        # Other ciphers
        'RC4-SHA',
        'RC4-MD5',
        'NULL-SHA256',
    ]

def check_ciphers(host, port):
    """Check all supported ciphers"""
    ciphers = get_all_ciphers()
    results = {}

    for cipher in ciphers:
        try:
            # Create new context for each cipher
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                context.set_ciphers(cipher)
            except ssl.SSLError:
                results[cipher] = False
                continue

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.do_handshake()
                    current_cipher = ssock.cipher()[0]
                    results[cipher] = (current_cipher == cipher)
        except Exception as e:
            if 'handshake failure' in str(e).lower() or 'no cipher match' in str(e).lower():
                results[cipher] = False
            else:
                results[cipher] = False

    return results

def format_cert_info(cert):
    """Format certificate information"""
    if not cert:
        return "Failed to get certificate information"

    info = []

    # Subject
    if 'subject' in cert:
        subject = []
        for item in cert['subject']:
            for attr in item:
                attr_name = {
                    'countryName': 'C',
                    'stateOrProvinceName': 'ST',
                    'localityName': 'L',
                    'organizationName': 'O',
                    'organizationalUnitName': 'OU',
                    'commonName': 'CN',
                    'emailAddress': 'Email',
                }.get(attr[0], attr[0])
                subject.append(f"{attr_name}={attr[1]}")
        info.append(f"Subject: {', '.join(subject)}")

    # Issuer
    if 'issuer' in cert:
        issuer = []
        for item in cert['issuer']:
            for attr in item:
                attr_name = {
                    'countryName': 'C',
                    'stateOrProvinceName': 'ST',
                    'localityName': 'L',
                    'organizationName': 'O',
                    'organizationalUnitName': 'OU',
                    'commonName': 'CN',
                }.get(attr[0], attr[0])
                issuer.append(f"{attr_name}={attr[1]}")
        info.append(f"Issuer: {', '.join(issuer)}")

    # Validity
    if 'notBefore' in cert:
        info.append(f"Valid From: {cert['notBefore']}")
    if 'notAfter' in cert:
        info.append(f"Valid To: {cert['notAfter']}")

    # Serial
    if 'serialNumber' in cert:
        info.append(f"Serial: {cert['serialNumber']}")

    # SANs
    if 'subjectAltName' in cert:
        sans = [f"{name_type}:{name}" for name_type, name in cert['subjectAltName']]
        info.append(f"Subject Alt Names: {', '.join(sans[:3])}" + ("..." if len(sans) > 3 else ""))

    return "\n".join(info)

def main():
    parser = argparse.ArgumentParser(description='SSL/TLS Scanner for Termux')
    parser.add_argument('host', help='Target host')
    parser.add_argument('-p', '--port', type=int, default=443, help='Port (default: 443)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    host = args.host
    port = args.port

    print(f"\n🔍 Scanning {host}:{port}")

    # Check if port is open
    if not check_port(host, port):
        print(f"\n❌ Error: Port {port} is closed or unreachable")
        return

    # Check protocol support
    print("\n🛡️ Checking protocol support...")
    protocols = check_tls_support(host, port)
    print("\n[+] Protocol Support:")
    for proto in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']:
        status = "✅ Supported" if protocols.get(proto, False) else "❌ Not supported"
        print(f"  {proto:8} {status}")

    # Get certificate info
    print("\n📄 Retrieving certificate information...")
    cert_info = get_certificate_info(host, port)
    print("\n[+] Certificate Information:")
    print(format_cert_info(cert_info))

    # Check cipher support
    print("\n🔑 Checking cipher support...")
    cipher_results = check_ciphers(host, port)

    # Group results
    print("\n[+] Cipher Support Results:")

    # Cipher groups
    groups = {
        "TLS 1.3": [],
        "ECDHE": [],
        "DHE": [],
        "AES": [],
        "Other": []
    }

    for cipher, supported in cipher_results.items():
        if 'TLS_AES' in cipher:
            groups["TLS 1.3"].append((cipher, supported))
        elif 'ECDHE' in cipher:
            groups["ECDHE"].append((cipher, supported))
        elif 'DHE' in cipher:
            groups["DHE"].append((cipher, supported))
        elif 'AES' in cipher:
            groups["AES"].append((cipher, supported))
        else:
            groups["Other"].append((cipher, supported))

    # Print by group
    for group_name, ciphers in groups.items():
        if not ciphers:
            continue

        print(f"\n  === {group_name} ===")
        for cipher, supported in ciphers:
            status = "✅" if supported else "❌"
            print(f"    {cipher:50} {status}")

    # Statistics
    total = len(cipher_results)
    supported = sum(1 for result in cipher_results.values() if result)
    print(f"\n📊 Summary: {supported}/{total} ciphers supported")

if __name__ == "__main__":
    main()
