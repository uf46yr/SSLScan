markdown
# SSL/TLS Scanner

A lightweight Python script to scan SSL/TLS configurations on remote servers. Works on both Linux systems and Termux (Android).

![Sample Output](https://via.placeholder.com/600x300?text=SSL+Scanner+Output+Example)

## Features

- Checks supported protocols (SSLv2, SSLv3, TLSv1.0 - TLSv1.3)
- Retrieves certificate information
- Tests support for 40+ cipher suites
- Color-coded results
- Works on Termux (Android)
- No external dependencies

## Requirements

- Python 3.6+
- OpenSSL libraries

## Installation

### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install python3 python3-pip
git clone [https://github.com/yourusername/ssl-scanner.git](https://github.com/uf46yr/SSLScan)
cd ssl-scanner
```

### Termux (Android)
```bash
pkg update
pkg install python openssl git
git clone [https://github.com/yourusername/ssl-scanner.git](https://github.com/uf46yr/SSLScan)
cd ssl-scanner
```

## Usage

Basic scan:
```bash
python sslscan.py example.com
```

Scan custom port:
```bash
python sslscan.py mail.example.com -p 587
```

Verbose output (shows errors):
```bash
python sslscan.py example.com -v
```

## Output Includes

1. **Protocol Support**:
   - SSLv2, SSLv3
   - TLSv1.0 - TLSv1.3
   - ✅/❌ status indicators

2. **Certificate Information**:
   - Subject and Issuer details
   - Validity dates
   - Subject Alternative Names
   - Serial number

3. **Cipher Checks**:
   - TLS 1.3 ciphers
   - ECDHE and DHE exchanges
   - AES and Camellia ciphers
   - Legacy ciphers (3DES, RC4)
   - Grouped results with status indicators

4. **Summary Statistics**:
   - Supported/Total ciphers count

## Sample Command
```bash
python sslscan.py google.com
```

## Output Example
```
🔍 Scanning google.com:443

🛡️ Checking protocol support...

[+] Protocol Support:
  SSLv2    ❌ Not supported
  SSLv3    ❌ Not supported
  TLSv1.0  ❌ Not supported
  TLSv1.1  ❌ Not supported
  TLSv1.2  ✅ Supported
  TLSv1.3  ✅ Supported

📄 Retrieving certificate information...

[+] Certificate Information:
Subject: CN=*.google.com
Issuer: C=US, O=Google Trust LLC, CN=GTS CA 1C3
Valid From: 2023-07-11 13:17:16
Valid To: 2023-10-03 13:17:15
Subject Alt Names: DNS:*.google.com, DNS:*.app...

🔑 Checking cipher support...

[+] Cipher Support Results:

  === TLS 1.3 ===
    TLS_AES_256_GCM_SHA384                     ✅
    TLS_CHACHA20_POLY1305_SHA256               ✅
    TLS_AES_128_GCM_SHA256                     ✅

  === ECDHE ===
    ECDHE-ECDSA-AES256-GCM-SHA384              ✅
    ECDHE-RSA-AES256-GCM-SHA384                ✅
    ECDHE-ECDSA-CHACHA20-POLY1305              ❌
    ...

📊 Summary: 28/40 ciphers supported
```

## Notes

- The script may take 30-60 seconds to complete (depends on server response)
- Some enterprise firewalls might block SSL scanning
- For accuracy, use on a stable internet connection
- Certificate information is retrieved without validation

## License
MIT
```

## Key sections explained:

1. **Compatibility**: Clearly mentions Linux and Termux support
2. **Installation**: Separate instructions for Linux and Termux
3. **Usage**: Practical examples with common flags
4. **Output**: Detailed explanation of each section
5. **Visual Cues**: Uses emojis and status indicators (✅/❌)
6. **Performance Note**: Warns about execution time
7. **Sample Output**: Shows realistic results format

The placeholder image link can be replaced with an actual screenshot once you capture the script's output. For enterprise environments, you might want to add a disclaimer about obtaining proper authorization before scanning.
