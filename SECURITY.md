# Security Policy

## Reporting Security Issues

Security and defensive reliability are core foundations of the **Network & Cybersecurity IT Support Toolkit**. If you discover a security vulnerability or potential flaw in our input sanitization, privilege boundaries, or subprocess execution, please report it responsibly.

### How to Report:
* **Do NOT open a public GitHub issue** for undisclosed security vulnerabilities.
* Please submit a detailed vulnerability report via private email to the project maintainer.
* Include:
  * Description of the vulnerability and its potential impact.
  * Exact steps to reproduce or Proof of Concept (PoC).
  * Affected modules and environment details (Windows version, Python version).

---

## Defensive Security Architecture & Standards

This project adheres to rigorous defensive engineering standards:

1. **Zero Command Injection (`shell=False`)**:
   * All external tool invocations (`ping`, `tracert`, `nslookup`, `ipconfig`, `powershell`) strictly enforce `subprocess.run(..., shell=False)` with argument lists.
   * User inputs (IP addresses, domain names, port numbers) are validated through strict regex and Python's `ipaddress` library before reaching the execution layer.
2. **Principle of Least Privilege**:
   * The toolkit operates safely under standard non-elevated user permissions.
   * Privileged operations (e.g. Security Event Log inspection) check elevation state dynamically and fail gracefully without crashing.
3. **No Credential Harvesting or Exfiltration**:
   * The application does not collect, log, or store passwords, Wi-Fi keys, private keys, or personal credentials.
   * Zero telemetry is transmitted to third-party servers. All diagnostics run locally against target endpoints specified by the operator.
4. **Non-Destructive Guarantee**:
   * Event logs are never cleared, deleted, or altered (`wevtutil cl` is strictly forbidden).
   * Disruptive network operations (such as DHCP lease release) require explicit user confirmation modals.

---

## Intellectual Property, Authenticity & Anti-Tampering Standards

The **Network & Cybersecurity IT Support Toolkit** is the original proprietary work of **Kwame_Theo** (All Rights Reserved):

1. **Cryptographic Provenance Seals (`core/integrity_guard.py`)**:
   * The software enforces an HMAC-SHA256 digital build seal calculated over immutable author credentials (`AUTHOR_NAME = "Kwame_Theo"`), origin UUIDs, and signature watermarks.
   * Modifying source code constants or attempting to claim unauthorized authorship triggers an immediate cryptographic integrity failure (`INTEGRITY ALERT`).
2. **Embedded Windows PE Binary Metadata**:
   * The standalone executable is compiled with embedded Windows resource metadata (`version_info.txt`), declaring Kwame_Theo as the author, copyright owner, and company in PE headers visible in Windows Explorer and Task Manager.
3. **Anti-Plagiarism & DMCA Compliance**:
   * Removal or alteration of embedded digital watermarks, copyright notices, or provenance headers is strictly prohibited under DMCA Title 17 U.S.C. § 1202.
4. **Production Obfuscation & Binary Hardening Options**:
   * For enterprise distribution requiring zero-decompilation protection:
     * **PyArmor**: `pyarmor gen --pack dist/NetSec_Toolkit/NetSec_Toolkit.exe app.py` (obfuscates Python bytecode with dynamic memory encryption and anti-debug hooks).
     * **Nuitka / Cython**: Compiles Python source files directly into native machine code (`.pyd` / `.dll` binaries) eliminating extractable Python bytecode entirely.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
