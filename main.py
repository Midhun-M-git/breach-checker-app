"""
Breach Checker CLI Engine
Validates password and credential exposure using the HaveIBeenPwned K-Anonymity API.
"""

import sys
import hashlib
import requests

def check_password_breach(password: str) -> int:
    """
    Checks if a password has been compromised in data breaches
    using k-anonymity model (only the first 5 chars of SHA-1 hash are sent).
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "Breach-Checker-CLI-Tool"}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Network error querying verification engine: {e}")
        return -1
        
    hashes = (line.split(':') for line in response.text.splitlines())
    for target_suffix, count in hashes:
        if target_suffix == suffix:
            return int(count)
    return 0

def check_email_exposure_notice():
    print("--------------------------------------------------")
    print("Email breach lookups require an authorized API key.")
    print("Visit https://haveibeenpwned.com/API/Key to configure.")
    print("--------------------------------------------------")

def main():
    print("==================================================")
    print("       Breach Checker Security Verification       ")
    print("==================================================")
    print("1. Check Password Compromise (K-Anonymity SHA-1)")
    print("2. Check Email Address Exposure")
    print("3. Exit")
    print("--------------------------------------------------")
    
    choice = input("Select an option (1-3): ").strip()
    
    if choice == '1':
        import getpass
        pwd = getpass.getpass("Enter password to check (input is hidden): ")
        if not pwd:
            print("Password cannot be empty.")
            return
            
        print("Checking secure hash range against global breach databases...")
        occurrences = check_password_breach(pwd)
        
        if occurrences > 0:
            print(f"[CRITICAL] This password appeared {occurrences:,} times in known data breaches!")
            print("[ADVISORY] We strongly recommend updating this credential immediately.")
        elif occurrences == 0:
            print("[SAFE] Good news: This password was NOT found in any known public breach databases.")
        else:
            print("[ERROR] Verification could not be completed at this time.")
            
    elif choice == '2':
        email = input("Enter email address: ").strip()
        print(f"Auditing email: {email}")
        check_email_exposure_notice()
        
    elif choice == '3':
        print("Exiting.")
        sys.exit(0)
    else:
        print("Invalid selection.")

if __name__ == '__main__':
    main()
