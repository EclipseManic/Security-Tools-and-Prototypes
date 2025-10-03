# Malware Analyzer CLI

**Author:** EclipseManic

Malware Analyzer CLI is a comprehensive, Python-based triage tool for rapid malware analysis. It combines a powerful suite of offline and online analysis techniques to provide a detailed and actionable assessment of potentially malicious files.

This tool is designed for security analysts, researchers, and developers who need a quick and efficient way to dissect suspicious files. By integrating with leading threat intelligence platforms, it delivers a holistic view of a file's risk profile, complete with a final score and detailed reports.

> ⚙️ Note: This project was developed with the assistance of AI tools to accelerate development and improve functionality.

---

## 🚀 Features

### Offline Analysis

* **File Hashes**: Calculates MD5 and SHA256 hashes for identification and lookups.
* **String Extraction**: Scans the binary for suspicious strings, including commands, URLs, registry keys, and file paths.
* **YARA Scanning**: Matches the file against a custom set of YARA rules (`rules.yar`) to detect known malware families and patterns.
* **PE Analysis** *(optional — requires `pefile`)*: Extracts critical information from Windows executables, such as imported functions, section details (e.g., entropy), and suspicious imports.

### Online Analysis

* **VirusTotal Integration**: Queries the VirusTotal v3 API to get the number of antivirus engines that flagged the file.
* **Hybrid-Analysis Integration**: Submits the file for a quick ML-based scan (CrowdStrike Falcon Sandbox or similar) and retrieves threat score/verdict.
* **MalwareBazaar Lookup**: Checks if the file hash is already present in the MalwareBazaar threat intelligence database.

### Risk Scoring & Reporting

* **Weighted Scoring Engine**: Calculates a final risk score from 0 to 100 based on findings from all analysis modules.
* **Risk Categorization**: Classifies the file as `LOW`, `MEDIUM`, or `HIGH` risk.
* **Multi-Format Reports**: Generates detailed reports in `TXT`, `HTML`, and `JSON` formats.
* **Rich Console Output**: Color-coded, easy-to-read summary directly in the terminal for immediate triage.

---

## 📦 Requirements

* **Python:** 3.8+

**Required libraries**

* `requests`
* `yara-python`
* `colorama`

**Optional**

* `pefile` (Enables PE file analysis)

**Note:** Valid API keys are required for the online scanning features.

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🔑 API Key Setup

This tool integrates with VirusTotal, Hybrid-Analysis, and MalwareBazaar. API keys must be placed in a `config.json` file in the same directory as the script. If keys are missing, corresponding online scans will be skipped automatically.

**Example `config.json`:**

```json
{
  "virustotal": {
    "api_key": "YOUR_VIRUSTOTAL_API_KEY"
  },
  "hybrid_analysis": {
    "api_key": "YOUR_HYBRID_ANALYSIS_API_KEY"
  },
  "malwarebazaar": {
    "api_key": "YOUR_MALWAREBAZAAR_API_KEY",
    "header": "Auth-Key"
  },
  "rate_limits": {
    "virustotal": 15,
    "hybrid_analysis": 5
  }
}
```

---

## 🔧 Usage

**Basic command**

```bash
python Malware_Analyzer.py <path_to_file_or_directory>
```

**Command-Line Flags**

* `--online`, `-o`: Force-enables all online scans.
* `--offline`, `-f`: Force-enables all offline scans.
* `--report-analysis`, `-r`: Generates report files. Specify formats like `-r txt,json`.

**Examples**

Full scan with reports:

```bash
python Malware_Analyzer.py samples/malware.exe -o -f -r txt,html,json
```

Offline scan only, no reports:

```bash
python Malware_Analyzer.py samples/suspicious.dll -f -r none
```

**Interactive Mode**

Run the script without flags to enter interactive mode. The script will prompt you to choose scan types (online/offline) and report formats. Ideal for first-time users.

---

## 📝 Example Output

```text
Scanning malware.exe ...

Scan summary: malware.exe
────────────────────────────────────────────────────────────
  MD5: e99a18c428cb38d5f260853678922e03
  SHA256: 2c26b46b68ffc68ff99b453c1d30413413422b4a4b8bdfab6e12e0a6f1b9e3e3
  Path: samples/malware.exe

Indicators
────────────────────────────────────────────────────────────
  VirusTotal: 25
  Hybrid-Analysis: 80
  YARA hits: 3
  MalwareBazaar match: True

Details
────────────────────────────────────────────────────────────
  Suspicious strings (sample):
    powershell
    http://malicious[.]com
    rundll32
    CreateRemoteThread
  YARA rules: rules.yar (approx 6)
  YARA hit: Trojan_Signature_1
  YARA hit: Suspicious_PowerShell
  PE sections:
    .text: size=6551040 entropy=6.78
    .rdata: size=3507200 entropy=5.03
  Suspicious imports: CreateRemoteThread, URLDownloadToFile

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ FINAL RISK SCORE: 100/100 (HIGH) ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

A detailed JSON report is also generated for integration with other tools and systems.
```

---

## 🤝 Contributing

Contributions are welcome. See `CONTRIBUTING.md` for guidelines on how to get started.

---

## 📄 License

This project is licensed under the **MIT License**. See the `LICENSE` file for more details.

---

## ⚠️ Disclaimer

This tool is intended for educational and defensive security purposes only. The author assumes no liability for misuse. Do not use this tool for malicious or illegal activities.
