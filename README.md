# Breach Checker App

<div align="center">

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Security](https://img.shields.io/badge/Security-K--Anonymity_SHA--1-E7352C?style=for-the-badge)](https://haveibeenpwned.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

</div>

A privacy-first security CLI validation engine that queries global vulnerability databases to determine whether credentials have been exposed in documented corporate security breaches.

---

## Verification Pipeline

```mermaid
graph LR
    Input[User Raw Credential] --> Hash[Local SHA-1 Cryptographic Hash]
    Hash --> Split[Partition: 5-Char Prefix and 35-Char Suffix]
    Split --> Send[Send Prefix Only to PwnedPasswords Range API]
    Send --> Response[Retrieve Hash Suffix Frequency Range]
    Response --> Match{Suffix Exists in Range?}
    Match -- Yes --> Warning[Flag as Compromised and Output Breach Frequency]
    Match -- No --> Verified[Verify Credential Integrity]
```

---

## Features

- **K-Anonymity Model**: Raw passwords never leave the local environment; only the first 5 hexadecimal characters of the SHA-1 hash are transmitted.
- **Instant Global Verification**: Queries hundreds of millions of exposed credentials cataloged in international data dumps.
- **Zero Third-Party Tracking**: Completely stateless, local, and telemetry-free execution.

---

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/Midhun-M-git/breach-checker-app.git
   cd breach-checker-app
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the verification CLI:
   ```bash
   python main.py
   ```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
