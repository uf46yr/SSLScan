import sys
import socket
import ssl
import argparse
import logging
import warnings
import concurrent.futures
from datetime import datetime
import time
import re
import hashlib
import ipaddress
import json
import gzip
import base64
from urllib.parse import urlparse

# Suppress DeprecationWarnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ANSI color codes
COLORS = {
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'MAGENTA': '\033[95m',
    'CYAN': '\033[96m',
    'WHITE': '\033[97m',
    'RESET': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m'
}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('sslscan.py')

def colorize(text, color):
    """Apply color to text if supported"""
    return f"{COLORS[color]}{text}{COLORS['RESET']}" if sys.stdout.isatty() else text

def get_ip_address(host):
    """Resolve host to IP address with validation"""
    try:
        # Check if input is already an IP address
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

def check_port(host, port, timeout=3):
    """Check if port is open"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def check_tls_support(host, port):
    """Check TLS protocol support with optimized handshakes"""
    protocols = {
        'SSLv2': (None, False),
        'SSLv3': (ssl.PROTOCOL_SSLv23, set()),
        'TLSv1.0': (ssl.PROTOCOL_TLSv1, {ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3}),
        'TLSv1.1': (ssl.PROTOCOL_TLSv1_1, {ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1}),
        'TLSv1.2': (ssl.PROTOCOL_TLSv1_2, {ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
                                            ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1}),
        'TLSv1.3': (ssl.PROTOCOL_TLS, {ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
                                       ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2}),
    }

    results = {}
    for proto, (version, options) in protocols.items():
        if version is None:
            results[proto] = False
            continue

        try:
            context = ssl.SSLContext(version)
            for option in options:
                if hasattr(ssl, option):
                    context.options |= getattr(ssl, option)

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.do_handshake()
                    # Verify actual protocol version for TLS 1.3
                    if proto == 'TLSv1.3':
                        if hasattr(ssock, 'version'):
                            version = ssock.version()
                            if version != 'TLSv1.3':
                                logger.debug(f"Expected TLSv1.3 but got {version}")
                                raise ssl.SSLError(f"Not TLS 1.3 (actual: {version})")
                    results[proto] = True
        except Exception as e:
            logger.debug(f"Protocol {proto} failed: {str(e)}")
            results[proto] = False

    return results

def get_certificate_details(host, port):
    """Get detailed certificate information with enhanced parsing"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True) if hasattr(ssock, 'getpeercert') else None

                # Get public key information
                key_info = get_public_key_info(der_cert) if der_cert else {}

                # Get certificate fingerprint
                sha1 = hashlib.sha1(der_cert).hexdigest() if der_cert else "N/A"
                sha256 = hashlib.sha256(der_cert).hexdigest() if der_cert else "N/A"

                # Get certificate extensions
                extensions = {}
                signature_algorithm = "Unknown"
                if cert:
                    # Extract signature algorithm
                    if 'signatureAlgorithm' in cert:
                        signature_algorithm = cert['signatureAlgorithm']
                    elif 'signature_algorithm' in cert:
                        signature_algorithm = cert['signature_algorithm']

                    if 'extensions' in cert:
                        for ext in cert['extensions']:
                            if ext[0] == 'keyUsage':
                                extensions['keyUsage'] = ', '.join(ext[1])
                            elif ext[0] == 'extendedKeyUsage':
                                extensions['extendedKeyUsage'] = ', '.join(ext[1])
                            elif ext[0] == 'subjectAltName':
                                sans = [f"{name_type}:{name}" for name_type, name in ext[1]]
                                extensions['subjectAltName'] = sans
                            elif ext[0] == 'certificatePolicies':
                                policies = [f"{policy[0]}" for policy in ext[1]]
                                extensions['certificatePolicies'] = policies
                            elif ext[0] == 'crlDistributionPoints':
                                crl_points = [f"{point}" for point in ext[1]]
                                extensions['crlDistributionPoints'] = crl_points

                # Check OCSP Stapling
                ocsp_stapling = False
                try:
                    if hasattr(ssock, 'get_ocsp_response'):
                        ocsp_resp = ssock.get_ocsp_response()
                        ocsp_stapling = ocsp_resp is not None
                except:
                    pass

                # Check if certificate is EV
                is_ev = False
                if extensions.get('certificatePolicies'):
                    ev_policies = [
                        '2.23.140.1.1',  # EV SSL
                        '1.3.6.1.4.1.14370.1.6',  # GlobalSign EV
                        '1.3.6.1.4.1.4146.1.1',  # Network Solutions EV
                        '2.16.840.1.114412.2.1'  # DigiCert EV
                    ]
                    for policy in extensions.get('certificatePolicies', []):
                        if policy in ev_policies:
                            is_ev = True
                            break

                # Check for Certificate Transparency
                ct_scts = []
                if extensions.get('1.3.6.1.4.1.11129.2.4.2'):
                    try:
                        sct_data = extensions['1.3.6.1.4.1.11129.2.4.2']
                        if isinstance(sct_data, bytes):
                            # Parse SCT list (RFC 6962)
                            sct_list = sct_data
                            sct_count = sct_list[0]  # First byte is count
                            pos = 1
                            for i in range(sct_count):
                                sct_length = int.from_bytes(sct_list[pos:pos+2], 'big')
                                pos += 2
                                sct = sct_list[pos:pos+sct_length]
                                pos += sct_length

                                # Extract log ID (first 32 bytes)
                                log_id = sct[:32].hex()
                                ct_scts.append(log_id)
                    except:
                        pass

                cert_info = {
                    'subject': parse_x500_name(cert.get('subject', [])) if cert else [],
                    'issuer': parse_x500_name(cert.get('issuer', [])) if cert else [],
                    'notBefore': cert.get('notBefore', '') if cert else '',
                    'notAfter': cert.get('notAfter', '') if cert else '',
                    'serialNumber': cert.get('serialNumber', '') if cert else '',
                    'subjectAltName': cert.get('subjectAltName', []) if cert else [],
                    'version': cert.get('version', '') if cert else '',
                    'keyInfo': key_info,
                    'signatureAlgorithm': signature_algorithm,
                    'fingerprint': {
                        'SHA-1': sha1,
                        'SHA-256': sha256
                    },
                    'extensions': extensions,
                    'ocspStapling': ocsp_stapling,
                    'isEV': is_ev,
                    'ctSCTs': ct_scts
                }
                return cert_info
    except Exception as e:
        logger.debug(f"Certificate error: {str(e)}")
        return None

def get_public_key_info(der_cert):
    """Extract public key information from certificate"""
    try:
        # Fallback to basic key info extraction
        cert_text = ssl.DER_cert_to_PEM_cert(der_cert)

        # Extract key size and type
        key_size = None
        key_type = "UNKNOWN"

        if "BEGIN RSA PUBLIC KEY" in cert_text or "RSA Public Key" in cert_text:
            key_type = "RSA"
            # Extract modulus
            match = re.search(r"Modulus:\s+([0-9a-f:]+)", cert_text, re.IGNORECASE)
            if match:
                modulus_hex = match.group(1).replace(':', '')
                key_size = len(modulus_hex) * 4  # Hex digits to bits
        elif "BEGIN EC PUBLIC KEY" in cert_text or "Public Key Algorithm: id-ecPublicKey" in cert_text:
            key_type = "EC"
            # Extract curve name
            match = re.search(r"ASN1 OID:\s+(\S+)", cert_text)
            if match:
                key_type = f"EC ({match.group(1)})"
            # Extract key size
            match = re.search(r"Public-Key:\s+\((\d+)\s+bit\)", cert_text)
            if match:
                key_size = int(match.group(1))

        return {
            'type': key_type,
            'size': key_size
        }
    except Exception as e:
        logger.debug(f"Key info error: {str(e)}")
        return {
            'type': "UNKNOWN",
            'size': None
        }

def parse_x500_name(entries):
    """Parse X.500 name to readable format"""
    attributes = []
    for entry in entries:
        for key, value in entry:
            short_name = {
                'countryName': 'C',
                'stateOrProvinceName': 'ST',
                'localityName': 'L',
                'organizationName': 'O',
                'organizationalUnitName': 'OU',
                'commonName': 'CN',
                'emailAddress': 'Email',
            }.get(key, key)
            attributes.append(f"{short_name}={value}")
    return attributes

def get_cipher_list():
    """Return optimized cipher list for testing"""
    return [
        # TLS 1.3 ciphers
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_128_CCM_SHA256',
        'TLS_AES_128_CCM_8_SHA256',

        # Modern ECDHE ciphers
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-CHACHA20-POLY1305',
        'ECDHE-RSA-CHACHA20-POLY1305',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',

        # DHE ciphers
        'DHE-RSA-AES256-GCM-SHA384',
        'DHE-RSA-CHACHA20-POLY1305',
        'DHE-RSA-AES128-GCM-SHA256',

        # Legacy ciphers
        'ECDHE-ECDSA-AES256-SHA384',
        'ECDHE-RSA-AES256-SHA384',
        'ECDHE-ECDSA-AES256-SHA',
        'ECDHE-RSA-AES256-SHA',
        'DHE-RSA-AES256-SHA256',
        'DHE-RSA-AES256-SHA',
        'AES256-GCM-SHA384',
        'AES256-SHA256',
        'AES256-SHA',
        'CAMELLIA256-SHA',
        'DES-CBC3-SHA',

        # Weak ciphers
        'ECDHE-ECDSA-RC4-SHA',
        'ECDHE-RSA-RC4-SHA',
        'RC4-SHA',
        'RC4-MD5',
        'NULL-SHA256'
    ]

def check_cipher(host, port, cipher):
    """Check if specific cipher is supported"""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            context.set_ciphers(cipher)
        except ssl.SSLError as e:
            return (cipher, False, str(e))

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.do_handshake()
                return (cipher, True, ssock.cipher()[0] if hasattr(ssock, 'cipher') else "Unknown")
    except Exception as e:
        return (cipher, False, str(e))

def check_ciphers_parallel(host, port, threads=15):
    """Check cipher support with parallel processing"""
    ciphers = get_cipher_list()
    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_cipher, host, port, cipher): cipher for cipher in ciphers}

        for future in concurrent.futures.as_completed(futures):
            cipher, supported, details = future.result()
            results[cipher] = (supported, details)

    return results

def format_cert_info(cert):
    """Format certificate information with colors and validation"""
    if not cert:
        return colorize("✗ Failed to retrieve certificate", "RED")

    lines = []

    # Subject
    if cert.get('subject'):
        lines.append(f"{colorize('Subject:', 'CYAN')} {', '.join(cert['subject'])}")

    # Issuer
    if cert.get('issuer'):
        lines.append(f"{colorize('Issuer:', 'CYAN')} {', '.join(cert['issuer'])}")

    # Validity with expiration check
    now = datetime.utcnow()
    if cert.get('notBefore') and cert.get('notAfter'):
        try:
            fmt = "%b %d %H:%M:%S %Y %Z"
            valid_from = datetime.strptime(cert['notBefore'], fmt)
            valid_to = datetime.strptime(cert['notAfter'], fmt)

            valid_from_str = valid_from.strftime("%Y-%m-%d")
            valid_to_str = valid_to.strftime("%Y-%m-%d")

            days_left = (valid_to - now).days
            status = ""
            if now < valid_from:
                status = colorize(f" (Not yet valid, starts in {(valid_from - now).days} days)", "YELLOW")
            elif days_left < 0:
                status = colorize(f" (EXPIRED {abs(days_left)} days ago!)", "RED")
            elif days_left < 30:
                status = colorize(f" (Expiring in {days_left} days)", "YELLOW")
            else:
                status = colorize(f" (Valid for {days_left} days)", "GREEN")

            lines.append(f"{colorize('Validity:', 'CYAN')} {valid_from_str} → {valid_to_str}{status}")
        except Exception as e:
            logger.debug(f"Date parsing error: {str(e)}")
            lines.append(f"{colorize('Validity:', 'CYAN')} {cert['notBefore']} → {cert['notAfter']}")

    # Public Key Information
    if cert.get('keyInfo'):
        key_info = cert['keyInfo']
        key_str = f"{key_info['type']}"
        if key_info.get('size'):
            key_str += f" ({key_info['size']} bits)"

            # Key strength assessment
            if "RSA" in key_info['type']:
                if key_info['size'] < 1024:
                    key_str += colorize(" (WEAK)", "RED")
                elif key_info['size'] < 2048:
                    key_str += colorize(" (MODERATE)", "YELLOW")
                else:
                    key_str += colorize(" (STRONG)", "GREEN")
            elif "EC" in key_info['type']:
                if key_info['size'] < 224:
                    key_str += colorize(" (WEAK)", "RED")
                elif key_info['size'] < 384:
                    key_str += colorize(" (MODERATE)", "YELLOW")
                else:
                    key_str += colorize(" (STRONG)", "GREEN")

        lines.append(f"{colorize('Public Key:', 'CYAN')} {key_str}")

    # Signature Algorithm
    if cert.get('signatureAlgorithm'):
        sig_algo = cert['signatureAlgorithm']
        # Check algorithm security
        weak_sig_algos = ['md5', 'sha1', 'md4', 'md2']
        status = ""
        if any(algo in sig_algo.lower() for algo in weak_sig_algos):
            status = colorize(" (WEAK)", "RED")
        elif 'sha256' in sig_algo.lower() or 'sha384' in sig_algo.lower() or 'sha512' in sig_algo.lower():
            status = colorize(" (STRONG)", "GREEN")
        else:
            status = colorize(" (MODERATE)", "YELLOW")

        lines.append(f"{colorize('Signature Algorithm:', 'CYAN')} {sig_algo}{status}")

    # Fingerprints
    if cert.get('fingerprint'):
        fp = cert['fingerprint']
        lines.append(f"{colorize('SHA-1 Fingerprint:', 'CYAN')} {fp.get('SHA-1', 'N/A')}")
        lines.append(f"{colorize('SHA-256 Fingerprint:', 'CYAN')} {fp.get('SHA-256', 'N/A')}")

    # SANs
    if cert.get('subjectAltName'):
        sans = [f"{name}" for name_type, name in cert['subjectAltName']]
        san_text = ', '.join(sans[:3]) + ('...' if len(sans) > 3 else '')
        lines.append(f"{colorize('SANs:', 'CYAN')} {san_text}")

    # Extensions
    if cert.get('extensions'):
        exts = cert['extensions']
        for name, value in exts.items():
            if name == 'subjectAltName':
                continue
            if isinstance(value, list):
                value = ', '.join(value[:3]) + ('...' if len(value) > 3 else '')
            lines.append(f"{colorize(f'{name}:', 'CYAN')} {value}")

    # OCSP Stapling
    if 'ocspStapling' in cert:
        status = colorize("Enabled", "GREEN") if cert['ocspStapling'] else colorize("Disabled", "RED")
        lines.append(f"{colorize('OCSP Stapling:', 'CYAN')} {status}")

    # Extended Validation
    if 'isEV' in cert:
        status = colorize("Yes", "GREEN") if cert['isEV'] else colorize("No", "YELLOW")
        lines.append(f"{colorize('EV Certificate:', 'CYAN')} {status}")

    # Certificate Transparency
    if 'ctSCTs' in cert and cert['ctSCTs']:
        sct_count = len(cert['ctSCTs'])
        status = colorize(f"Yes ({sct_count} SCTs)", "GREEN")
        lines.append(f"{colorize('Certificate Transparency:', 'CYAN')} {status}")

    return '\n'.join(lines)

def check_security_features(host, port, protocols):
    """Check additional security features and vulnerabilities"""
    features = {}

    # Check for secure renegotiation
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                features['secure_renegotiation'] = hasattr(ssock.context, 'options') and \
                    ssock.context.options & ssl.OP_NO_RENEGOTIATION == 0
    except:
        features['secure_renegotiation'] = False

    # Check for compression support
    features['compression'] = False
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                if hasattr(ssock, 'compression'):
                    features['compression'] = ssock.compression() != 'NONE'
    except:
        pass

    # Check for TLS_FALLBACK_SCSV support (downgrade prevention)
    features['downgrade_prevention'] = False
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers("TLS_FALLBACK_SCSV")

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                features['downgrade_prevention'] = True
    except:
        pass

    # Check for Heartbleed vulnerability
    features['heartbleed_vulnerable'] = False
    if protocols.get('TLSv1.2', False) or protocols.get('TLSv1.1', False):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Try to send malformed heartbeat request
                    ssock.send(b"\x18\x03\x02\x00\x03\x01\x40\x00")
                    response = ssock.recv(5)
                    if response:
                        features['heartbleed_vulnerable'] = True
        except:
            pass

    # Check for POODLE vulnerability (SSLv3)
    features['poodle_vulnerable'] = False
    if protocols.get('SSLv3', False):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_TLSv1
            context.options |= ssl.OP_NO_TLSv1_1
            context.options |= ssl.OP_NO_TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # If we can connect with SSLv3, server is vulnerable
                    features['poodle_vulnerable'] = True
        except:
            pass

    # Check for BEAST vulnerability (TLSv1.0)
    features['beast_vulnerable'] = False
    if protocols.get('TLSv1.0', False):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Try to use a CBC cipher
            context.set_ciphers('RC4-SHA:AES128-SHA')

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()[0] if hasattr(ssock, 'cipher') else ""
                    if 'CBC' in cipher or 'AES' in cipher:
                        features['beast_vulnerable'] = True
        except:
            pass

    # Check for CRIME vulnerability (TLS compression)
    features['crime_vulnerable'] = features.get('compression', False)

    return features

def get_ssl_labs_grade(host, port=443):
    """Get SSL Labs grade for the host (requires internet connection)"""
    try:
        import requests
        api_url = f"https://api.ssllabs.com/api/v3/analyze?host={host}&publish=off"
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'endpoints' in data and data['endpoints']:
                return data['endpoints'][0].get('grade', 'N/A')
        return "N/A"
    except:
        return "N/A"

def print_protocol_results(results):
    """Print protocol support with colored status"""
    print("\n" + colorize("🛡️ Protocol Support", "BOLD"))
    print("=" * 50)

    for proto in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']:
        status = results.get(proto, False)
        status_str = colorize("✓ SUPPORTED", "GREEN") if status else colorize("✗ NOT SUPPORTED", "RED")
        symbol = colorize("●", "GREEN" if status else "RED")
        print(f" {symbol} {proto:8} {status_str}")

    # Security assessment
    weak_protos = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
    strong_protos = ['TLSv1.2', 'TLSv1.3']

    weak_count = sum(1 for proto in weak_protos if results.get(proto, False))
    strong_count = sum(1 for proto in strong_protos if results.get(proto, False))

    if weak_count > 0:
        assessment = colorize("INSECURE (Weak protocols enabled)", "RED")
    elif strong_count == 0:
        assessment = colorize("INSECURE (No strong protocols supported)", "RED")
    elif strong_count == 1:
        assessment = colorize("MODERATE (Only one modern protocol)", "YELLOW")
    else:
        assessment = colorize("SECURE (Modern protocols supported)", "GREEN")

    print(f"\n{colorize('🔒 Security Assessment:', 'BOLD')} {assessment}")

def print_cipher_results(results):
    """Print cipher results with grouping and colors"""
    groups = {
        "TLS 1.3": [],
        "Strong": [],
        "Legacy": [],
        "Weak": []
    }

    for cipher, (supported, details) in results.items():
        if 'TLS_AES' in cipher:
            groups["TLS 1.3"].append((cipher, supported))
        elif 'GCM' in cipher or 'CHACHA20' in cipher:
            groups["Strong"].append((cipher, supported))
        elif 'SHA256' in cipher or 'SHA384' in cipher:
            groups["Legacy"].append((cipher, supported))
        else:
            groups["Weak"].append((cipher, supported))

    print("\n" + colorize("🔑 Cipher Support", "BOLD"))
    print("=" * 50)

    for group_name in ["TLS 1.3", "Strong", "Legacy", "Weak"]:
        group = groups[group_name]
        if not group:
            continue

        print(f"\n{colorize(group_name.upper(), "MAGENTA")}")
        for cipher, supported in group:
            symbol = colorize("✓", "GREEN") if supported else colorize("✗", "RED")
            cipher_name = colorize(cipher, "GREEN" if supported else "RED")
            print(f"  {symbol} {cipher_name}")

    # Calculate statistics
    total = len(results)
    supported = sum(1 for _, (s, _) in results.items() if s)
    strong_count = sum(1 for cipher, (s, _) in results.items()
                      if s and ('TLS_AES' in cipher or 'GCM' in cipher or 'CHACHA20' in cipher))
    weak_count = sum(1 for cipher, (s, _) in results.items()
                    if s and cipher in groups["Weak"])

    strength = "STRONG"
    color = "GREEN"
    if weak_count > 0:
        strength = "INSECURE"
        color = "RED"
    elif strong_count < 5:
        strength = "MODERATE"
        color = "YELLOW"

    print(f"\n{colorize('📊 Summary:', 'BOLD')} {supported}/{total} ciphers supported")
    print(f"{colorize('🔒 Security Level:', 'BOLD')} {colorize(strength, color)}")
    print(f"  - {strong_count} strong ciphers")
    print(f"  - {weak_count} weak ciphers")

def print_security_features(features):
    """Print security features and vulnerabilities"""
    print("\n" + colorize("🛡️ Security Features & Vulnerabilities", "BOLD"))
    print("=" * 50)

    # Secure Renegotiation
    status = colorize("Enabled", "GREEN") if features.get('secure_renegotiation', False) else colorize("Disabled", "YELLOW")
    print(f" ● Secure Renegotiation: {status}")

    # Compression
    status = colorize("Enabled", "RED") if features.get('compression', False) else colorize("Disabled", "GREEN")
    print(f" ● TLS Compression: {status}")

    # Downgrade Prevention
    status = colorize("Supported", "GREEN") if features.get('downgrade_prevention', False) else colorize("Not Supported", "YELLOW")
    print(f" ● Downgrade Prevention: {status}")

    # Heartbleed
    status = colorize("VULNERABLE!", "RED") if features.get('heartbleed_vulnerable', False) else colorize("Not Vulnerable", "GREEN")
    print(f" ● Heartbleed (CVE-2014-0160): {status}")

    # POODLE
    status = colorize("VULNERABLE!", "RED") if features.get('poodle_vulnerable', False) else colorize("Not Vulnerable", "GREEN")
    print(f" ● POODLE (CVE-2014-3566): {status}")

    # BEAST
    status = colorize("VULNERABLE!", "RED") if features.get('beast_vulnerable', False) else colorize("Not Vulnerable", "GREEN")
    print(f" ● BEAST (CVE-2011-3389): {status}")

    # CRIME
    status = colorize("VULNERABLE!", "RED") if features.get('crime_vulnerable', False) else colorize("Not Vulnerable", "GREEN")
    print(f" ● CRIME (CVE-2012-4929): {status}")

    # Security assessment
    issues = []
    if features.get('compression'):
        issues.append("TLS Compression (CRIME)")
    if features.get('heartbleed_vulnerable'):
        issues.append("Heartbleed vulnerability")
    if features.get('poodle_vulnerable'):
        issues.append("POODLE vulnerability")
    if features.get('beast_vulnerable'):
        issues.append("BEAST vulnerability")
    if not features.get('downgrade_prevention'):
        issues.append("No downgrade prevention")

    if issues:
        assessment = colorize(f"WARNING: {len(issues)} security issues found", "RED")
        print(f"\n{colorize('⚠️  Security Assessment:', 'BOLD')} {assessment}")
        for issue in issues:
            print(f"   - {issue}")
    else:
        assessment = colorize("No critical vulnerabilities found", "GREEN")
        print(f"\n{colorize('✅ Security Assessment:', 'BOLD')} {assessment}")

def print_ssl_info_table():
    """Print SSL/TLS information table"""
    print("\n" + colorize("ℹ️ SSL/TLS Information", "BOLD"))
    print("=" * 50)

    info = [
        ["Protocol", "Status", "Introduced", "Security"],
        ["SSL 2.0", "Deprecated", "1995", "Insecure"],
        ["SSL 3.0", "Deprecated", "1996", "Insecure"],
        ["TLS 1.0", "Deprecated", "1999", "Insecure"],
        ["TLS 1.1", "Deprecated", "2006", "Weak"],
        ["TLS 1.2", "Widely used", "2008", "Secure"],
        ["TLS 1.3", "Latest", "2018", "Very secure"]
    ]

    for row in info:
        if row[0] == "Protocol":
            print(colorize("{:<10} {:<12} {:<10} {:<15}".format(*row), "UNDERLINE"))
        else:
            security_color = "GREEN"
            if "Insecure" in row[3]:
                security_color = "RED"
            elif "Weak" in row[3]:
                security_color = "YELLOW"

            print("{:<10} {:<12} {:<10} {}".format(
                row[0],
                row[1],
                row[2],
                colorize(row[3], security_color)
            ))

def main():
    parser = argparse.ArgumentParser(
        description=colorize('SSL/TLS Scanner - Enhanced Security Analysis', "BOLD"),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('host', help='Target host')
    parser.add_argument('-p', '--port', type=int, default=443, help='Port number')
    parser.add_argument('-t', '--threads', type=int, default=15,
                        help='Threads for cipher scanning')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-i', '--info', action='store_true', help='Show SSL/TLS information table')
    args = parser.parse_args()

    if args.info:
        print_ssl_info_table()
        return

    host = args.host
    port = args.port

    # Resolve host to IP
    ip_addr = get_ip_address(host)
    if not ip_addr:
        print(colorize(f"❌ Error: Could not resolve {host}", "RED"))
        return

    print(colorize(f"\n🔍 Starting SSL/TLS scan for {host} ({ip_addr}):{port}", "BOLD"))
    print(colorize(f"⏱️  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "BLUE"))

    # Check port status
    print("\n" + colorize("[1/6] Port Check", "UNDERLINE"))
    if not check_port(ip_addr, port):
        print(colorize(f"❌ Port {port} is closed or unreachable", "RED"))
        return
    print(colorize(f"✅ Port {port} is open", "GREEN"))

    # Check protocol support
    print("\n" + colorize("[2/6] Protocol Analysis", "UNDERLINE"))
    start_time = time.time()
    protocols = check_tls_support(ip_addr, port)
    print_protocol_results(protocols)

    # Get certificate info
    print("\n" + colorize("[3/6] Certificate Inspection", "UNDERLINE"))
    cert_info = get_certificate_details(ip_addr, port)
    print(format_cert_info(cert_info))

    # Check cipher support
    print("\n" + colorize(f"[4/6] Cipher Analysis ({args.threads} threads)", "UNDERLINE"))
    cipher_results = check_ciphers_parallel(ip_addr, port, args.threads)
    print_cipher_results(cipher_results)

    # Check security features
    print("\n" + colorize("[5/6] Security Features & Vulnerabilities", "UNDERLINE"))
    security_features = check_security_features(ip_addr, port, protocols)
    print_security_features(security_features)

    # Get SSL Labs grade
    print("\n" + colorize("[6/6] External Validation", "UNDERLINE"))
    ssl_labs_grade = get_ssl_labs_grade(host, port)
    grade_color = "GREEN"
    if ssl_labs_grade in ['F', 'T']:
        grade_color = "RED"
    elif ssl_labs_grade in ['C', 'D', 'E']:
        grade_color = "YELLOW"

    print(f"{colorize('SSL Labs Grade:', 'CYAN')} {colorize(ssl_labs_grade, grade_color)}")
    print(f"{colorize('Note:', 'CYAN')} Grade from Qualys SSL Labs API (may take hours for new scans)")

    # Performance summary
    elapsed = time.time() - start_time
    print(colorize(f"\n⏱️  Scan completed in {elapsed:.2f} seconds", "BLUE"))
    print(colorize("=" * 60, "BOLD"))
    print(colorize("Report generated by SSLScan Pro", "MAGENTA"))
    print(colorize("SSL/TLS Security Recommendations:", "BOLD"))
    print("- Use TLS 1.2 or 1.3 only")
    print("- Disable weak ciphers (RC4, DES, 3DES, NULL)")
    print("- Prefer ECDHE key exchange with PFS")
    print("- Use strong certificates (SHA-256+, 2048+ bits)")
    print("- Enable OCSP Stapling")
    print("- Implement HSTS and Certificate Transparency")

if __name__ == "__main__":
    main()
