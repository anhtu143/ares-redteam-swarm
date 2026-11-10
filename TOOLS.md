# ARES FRAMEWORK - TOOLS INVENTORY (v2.0)

This document defines the weaponized toolset available to the ARES framework, categorized by the Cyber Kill Chain.

## 1. RECONNAISSANCE & ENUMERATION
- **Amass / Subfinder:** Subdomain enumeration.
- **Naabu / RustScan:** Fast port scanning.
- **Nuclei:** Template-based vulnerability scanning (Custom Red Team templates).
- **BloodHound / SharpHound:** Active Directory privilege escalation path mapping.
- **Ffuf / Feroxbuster:** Advanced directory and API endpoint fuzzing.

## 2. WEAPONIZATION & EXPLOITATION
- **Metasploit Framework (MSF):** Used via RPC for automated exploit delivery.
- **Impacket:** Core toolkit for SMB, WMI, and MSSQL lateral movement and exploitation.
- **SQLMap:** Automated SQL injection with tamper scripts for WAF evasion.
- **Custom Exploit Engine:** Python-based module for rapid 0-day/1-day PoC execution.

## 3. COMMAND & CONTROL (C2)
ARES interacts with C2 frameworks via their APIs to manage beacons and listeners.
- **Mythic C2:** Cross-platform, heavily utilized for macOS/Linux persistence.
- **Sliver:** Go-based C2 for Windows/Linux, utilizing mTLS, WireGuard, and DNS.
- **Cobalt Strike:** (If licensed/provided by USER) Integrated via external C2 specification for advanced Windows evasion.

## 4. POST-EXPLOITATION & EVASION
- **Mimikatz / Rubeus:** Credential dumping and Kerberos abuse.
- **PEASS-ng (LinPEAS / WinPEAS):** Local privilege escalation vectors.
- **Donut:** Generating position-independent shellcode from .NET Assemblies.
- **ScareCrow / InvisibilityCloak:** Payload obfuscation to bypass EDR/AV.

## 5. OPSEC WRAPPERS (Crucial)
ARES does not run tools blindly. It uses OPSEC wrappers:
- `proxychains4`: All network traffic routed through TOR or compromised pivot points.
- `sleep / jitter`: Introduced into all brute-force or fuzzing tasks to avoid rate-limiting.
- `cleanup.sh`: Automated script to wipe logs, bash history, and temporary files upon exit.
