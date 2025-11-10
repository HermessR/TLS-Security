#!/usr/bin/env python3
import subprocess
import argparse
from datetime import datetime
import json
import requests 

def run_command(cmd_list, timeout=15):
    """Run a command list and return its output."""
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out: {' '.join(cmd_list)}")
        return ""

def run_openssl_scan(host):
    print("[+] Fetching certificate with OpenSSL...")
    # Use bash to handle input redirection safely
    cmd = ["bash", "-c", f"openssl s_client -connect {host}:443 -servername {host} -showcerts < /dev/null"]
    return run_command(cmd)

def check_certificate_expiry(cert_output):
    begin = cert_output.find("-----BEGIN CERTIFICATE-----")
    end = cert_output.find("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
    if begin == -1 or end == -1:
        print("[!] No certificate block found.")
        return

    cert_block = cert_output[begin:end]
    cmd = ["openssl", "x509", "-noout", "-enddate"]
    try:
        result = subprocess.run(cmd, input=cert_block, capture_output=True, text=True, timeout=10)
        output = result.stdout.strip()
    except subprocess.TimeoutExpired:
        print("[!] Certificate parsing timed out.")
        return

    if "notAfter=" in output:
        expiry_str = output.split('=')[1].strip()
        try:
            expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            print(f"[✓] Certificate expires on: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        except ValueError:
            print(f"[✓] Certificate expires on: {expiry_str}")
    else:
        print("[!] Could not parse expiry date.")

def check_hsts(host, json_mode=False):
    print("[+] Checking HSTS header...")
    cmd = ["curl", "-sIL", "--compressed", "-H", "User-Agent: Mozilla", f"https://{host}"]
    headers = run_command(cmd)

    hsts_line = next((line for line in headers.splitlines() if "Strict-Transport-Security" in line), None)
    result = {
        "hsts_present": bool(hsts_line),
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
        "preload_eligible": None,
        "warnings": []
    }

    if not hsts_line:
        print("[!] HSTS is missing")
        result["warnings"].append("HSTS header missing")
    else:
        print("[✓] HSTS header found")
        print(f"    → {hsts_line.strip()}")

        if "max-age=" in hsts_line.lower():
            try:
                max_age = int(re.search(r"max-age=(\d+)", hsts_line, re.IGNORECASE).group(1))
                result["max_age"] = max_age
                days = max_age // 86400
                print(f"    • max-age: {max_age} seconds ({days} days)")
                if max_age < 15768000:
                    result["warnings"].append("max-age below recommended 6 months")
            except Exception:
                result["warnings"].append("Could not parse max-age")
        else:
            result["warnings"].append("max-age directive missing")

        result["include_subdomains"] = "includesubdomains" in hsts_line.lower()
        result["preload"] = "preload" in hsts_line.lower()

        if not result["include_subdomains"]:
            result["warnings"].append("includeSubDomains missing")
        if not result["preload"]:
            result["warnings"].append("preload directive missing")

        # Check preload eligibility
        try:
            preload_check = requests.get(f"https://hstspreload.org/api/v2/preloadable?domain={host}", timeout=10)
            if preload_check.ok:
                preload_data = preload_check.json()
                result["preload_eligible"] = preload_data.get("preloadable", False)
                if preload_data.get("errors"):
                    result["warnings"].extend(preload_data["errors"])
        except Exception:
            result["warnings"].append("Preload eligibility check failed")

    if json_mode:
        print(json.dumps(result, indent=2))

def run_nmap_cipher_scan(host):
    print("\n[+] Running Nmap TLS cipher scan...")
    cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", host]
    output = run_command(cmd, timeout=60)
    print(output)

    if "TLSv1.0" in output or "TLSv1.1" in output:
        print("[!] Deprecated TLS versions supported (1.0/1.1)")
    if "3DES" in output:
        print("[!] Weak cipher 3DES detected (SWEET32 risk)")

def scan_host(host, run_nmap=False):
    print(f"\n🔍 Scanning TLS configuration for: {host}\n")
    cert_info = run_openssl_scan(host)
    check_certificate_expiry(cert_info)
    check_hsts(host)
    if run_nmap:
        run_nmap_cipher_scan(host)

def main():
    parser = argparse.ArgumentParser(description="TLS Misconfiguration Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Target domain or IP")
    group.add_argument("--targets", help="File containing list of domains")
    parser.add_argument("--nmap", action="store_true", help="Run Nmap cipher scan")
    args = parser.parse_args()

    if args.host:
        scan_host(args.host, run_nmap=args.nmap)
    elif args.targets:
        try:
            with open(args.targets) as f:
                for line in f:
                    host = line.strip()
                    if host:
                        scan_host(host, run_nmap=args.nmap)
        except FileNotFoundError:
            print(f"[!] File not found: {args.targets}")

if __name__ == "__main__":
    main()
