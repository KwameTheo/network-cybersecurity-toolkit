/**
 * AegisVault Studio - Software Catalog Database
 * Central data registry for all software created by Kwame Theo.
 */

const DEFAULT_SOFTWARE_CATALOG = [
  {
    id: "netsec-toolkit",
    title: "Network & Cybersecurity IT Support Toolkit",
    tagline: "Enterprise Windows IT Diagnostics, Network Engineering, Digital Forensics & CIS Compliance Suite",
    version: "v1.5.0",
    releaseDate: "2026-09-04",
    status: "Latest Stable",
    featured: true,
    category: "security-network",
    platform: "Windows 10 / 11 (x64)",
    icon: "shield-check",
    badge: "15 Engines • 94 Tests",
    author: "Kwame_Theo",
    githubUrl: "https://github.com/KwameTheo/network-cybersecurity-toolkit",
    downloadUrl: "https://github.com/KwameTheo/network-cybersecurity-toolkit/releases/download/v1.5.0/NetSec_Toolkit_v1.5.0_Windows_x64.zip",
    fileSize: "23.8 MB (Standalone Portable)",
    sha256: "04F53FACB10C3B94C847E99DCF81B15E98B14644EC5BD29D45DA5EF5BDDE89EF",
    summary: "A high-performance Windows desktop application built with Python (CustomTkinter + SQLite + ReportLab) uniting 15 operational tools for network triage, real-time DGA threat detection, USB registry forensics, and automated PDF audit reporting.",
    tags: ["Python", "CustomTkinter", "Cybersecurity", "Network Diagnostics", "Digital Forensics", "SQLite", "ReportLab", "PyInstaller"],
    stats: {
      modules: 15,
      tests: "94 / 94 Passing",
      architecture: "Model-View-Controller (Decoupled Engines)",
      security: "Zero Shell Injection (RFC Sanitized)"
    },
    features: [
      {
        name: "Subnet IP Scanner & LAN Mapper",
        description: "254-host multithreaded ARP sweep with IEEE OUI MAC vendor decoding and rogue device tagging."
      },
      {
        name: "Live DNS Query Threat Monitor",
        description: "Real-time DNS telemetry utilizing Shannon Entropy algorithms to detect DGA botnet domains and tunneling exfiltration."
      },
      {
        name: "USB Device Forensics Audit",
        description: "Extracts historical USBSTOR registry artifacts, hardware serial numbers, VID/PID, and live peripheral mounts."
      },
      {
        name: "MITRE ATT&CK Persistence Inspector",
        description: "Audits Registry Run keys, Startup folders, and Scheduled Tasks for malicious persistence scripts."
      },
      {
        name: "6-Stage OSI Health Ladder",
        description: "Sequential diagnostics traversing link-state, gateway, DNS root, public IP, and SSL/TLS handshakes."
      },
      {
        name: "CIS Defensive Security Baseline Audit",
        description: "Evaluates Windows Firewall, Defender, UAC elevation, Guest accounts, SMBv1 vulnerabilities, and BitLocker."
      },
      {
        name: "Automated ReportLab PDF & SQLite History",
        description: "Exports print-ready executive diagnostic PDF reports, CSV, JSON, and tracks longitudinal audit records."
      }
    ],
    requirements: [
      "Windows 10 or Windows 11 (64-bit)",
      "Zero installation required (Standalone Portable .exe)",
      "Administrator privileges required for deep hardware/registry scans"
    ],
    changelog: [
      "v1.5.0 - Integrated Cryptographic Provenance Guard, 94 unit tests, and GitHub Actions matrix CI/CD.",
      "v1.4.0 - Added Subnet IP Scanner, Wi-Fi Channel Overlap Analyzer, and Shannon Entropy DNS Inspector.",
      "v1.3.0 - Added USB Forensics and MITRE ATT&CK Persistence Inspector.",
      "v1.0.0 - Initial release with 10 core diagnostic engines."
    ]
  },
  {
    id: "dns-entropy-detector",
    title: "Shannon Entropy DGA Threat Inspector",
    tagline: "Lightweight algorithmic domain detection engine for identifying Command & Control botnet traffic",
    version: "v1.1.0",
    releaseDate: "2026-08-20",
    status: "Stable",
    featured: false,
    category: "security-network",
    platform: "Cross-Platform (Python / CLI)",
    icon: "activity",
    badge: "Cyber Threat Intel",
    author: "Kwame_Theo",
    githubUrl: "https://github.com/KwameTheo/network-cybersecurity-toolkit",
    downloadUrl: "https://github.com/KwameTheo/network-cybersecurity-toolkit",
    fileSize: "1.2 MB",
    sha256: "E89AF912C0984DEB9183427E890B15CDE8914644EC5BD29D45DA5EF5BDDE1234",
    summary: "Stand-alone statistical analysis tool implementing Shannon Entropy calculations to detect domain generation algorithms (DGAs), DNS data exfiltration, and high-entropy malicious hostnames.",
    tags: ["Threat Hunting", "DNS", "Algorithms", "SOC Tools", "Python"],
    stats: {
      modules: 3,
      tests: "12 / 12 Passing",
      architecture: "Headless CLI / API",
      security: "Cryptographic Analysis"
    },
    features: [
      {
        name: "Shannon Entropy Scoring",
        description: "Calculates character distribution randomness to differentiate human domain names from malware DGAs."
      },
      {
        name: "Suspicious TLD Heuristics",
        description: "Automated flagging of high-risk top-level domains commonly abused in phishing and malware campaigns."
      },
      {
        name: "Tunneling Payload Length Detection",
        description: "Detects oversized subdomains indicative of DNS tunneling and data exfiltration."
      }
    ],
    requirements: [
      "Python 3.10+ (Any OS) or Windows standalone binary",
      "Network packet capture permissions (optional for live sniff mode)"
    ],
    changelog: [
      "v1.1.0 - Enhanced RFC 1035 compliance and added JSON stream output.",
      "v1.0.0 - Core entropy scoring engine."
    ]
  },
  {
    id: "usb-forensic-hunter",
    title: "USBSTOR Digital Forensics Artifact Parser",
    tagline: "Incident response utility for reconstructing historical USB storage device connection timelines",
    version: "v1.2.0",
    releaseDate: "2026-08-15",
    status: "Stable",
    featured: false,
    category: "forensics",
    platform: "Windows 10 / 11 (x64)",
    icon: "hard-drive",
    badge: "DFIR / Forensics",
    author: "Kwame_Theo",
    githubUrl: "https://github.com/KwameTheo/network-cybersecurity-toolkit",
    downloadUrl: "https://github.com/KwameTheo/network-cybersecurity-toolkit",
    fileSize: "2.5 MB",
    sha256: "7F8A9E1D4B2C4E6A8F3D9A1B2C3D4E5F04F53FACB10C3B94C847E99DCF81B15E",
    summary: "Specialized digital forensics artifact extractor targeting Windows Registry USBSTOR keys, device properties, serial numbers, and mounting points for rapid cyber incident triage.",
    tags: ["Forensics", "DFIR", "Windows Registry", "Incident Response", "Python"],
    stats: {
      modules: 4,
      tests: "16 / 16 Passing",
      architecture: "Direct Registry Parser",
      security: "Read-Only Non-Destructive"
    },
    features: [
      {
        name: "Historical Registry Sweep",
        description: "Parses HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR to unmask all previously connected thumb drives."
      },
      {
        name: "Hardware Serial Number Extraction",
        description: "Retrieves unique manufacturer serial numbers to attribute specific physical hardware."
      },
      {
        name: "Live Mount Correlation",
        description: "Matches historical registry artifacts against active mounted volumes and drive letters."
      }
    ],
    requirements: [
      "Windows 10 or Windows 11",
      "Standard User or Local Administrator"
    ],
    changelog: [
      "v1.2.0 - Added vendor & product ID decoding and CSV forensic export.",
      "v1.0.0 - Initial registry extraction parser."
    ]
  }
];

// Helper functions for persistent catalog storage
const STORAGE_KEY = "aegisvault_software_catalog";

function getSoftwareCatalog() {
  const customCatalog = localStorage.getItem(STORAGE_KEY);
  if (customCatalog) {
    try {
      const parsed = JSON.parse(customCatalog);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed;
      }
    } catch (e) {
      console.warn("Could not parse saved catalog from localStorage, using default.", e);
    }
  }
  return DEFAULT_SOFTWARE_CATALOG;
}

function saveSoftwareCatalog(catalog) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(catalog));
}

function resetSoftwareCatalogToDefault() {
  localStorage.removeItem(STORAGE_KEY);
  return DEFAULT_SOFTWARE_CATALOG;
}
