# Malware Analyzer CLI

**Author:** EclipseManic  

Malware Analyzer CLI is a comprehensive, Python-based triage tool for rapid malware analysis. It combines a powerful suite of offline and online analysis techniques to provide a detailed and actionable assessment of potentially malicious files.

This tool is designed for security analysts, researchers, and developers who need a quick and efficient way to dissect suspicious files. By integrating with leading threat intelligence platforms like VirusTotal and Hybrid-Analysis, it delivers a holistic view of a file's risk profile, complete with a final score and detailed reports in multiple formats (TXT, HTML, and PDF).

---

## 🚀 Features

### Offline Analysis
- **Hashes** → MD5, SHA256  
- **String Extraction** → Detects suspicious commands, registry keys, URLs, paths  
- **YARA Rules** → Scans against custom signatures (`rules.yar`)  
- **PE Analysis** (if `pefile` installed) → Extracts imports, section entropy, suspicious imports  

### Online Analysis
- **VirusTotal v3** → File scanning and detection counts  
- **Hybrid-Analysis (CrowdStrike Falcon Sandbox)** → Quick ML-based scan and verdict  
- **MalwareBazaar Lookup** → Checks if sample already exists in threat databases  

### Risk Scoring
- Weighted scoring from multiple sources  
- Final score: **0–100**  
- Categorized as **LOW**, **MEDIUM**, or **HIGH** risk  
- Overrides to 100% malicious if authoritative detection found  

### Reports
- Generates **TXT, HTML, and PDF** reports (configurable)  
- Detailed breakdown of detections and indicators  
- Color-coded console output for quick triage  

---

## 📦 Requirements

- Python **3.8+**  
- Required libraries:  
  - `requests`, `yara-python`, `colorama`, `fpdf`, `concurrent.futures`  
- Optional libraries:  
  - `pefile` → PE file analysis  
- Online scanning requires valid API keys  

### Install Dependencies
```bash
pip install -r requirements.txt
```
## 🔑 API Key Setup

This tool supports integration with **VirusTotal** and **Hybrid-Analysis**. API keys are loaded from a `config.json` file located in the same directory as the script.

### Example `config.json`:

`{   "virustotal": {     "api_key": "YOUR_VIRUSTOTAL_API_KEY"   },   "hybrid_analysis": {     "api_key": "YOUR_HYBRID_ANALYSIS_API_KEY"   },   "rate_limits": {     "virustotal": 15,     "hybrid_analysis": 5   } }`

-   `rate_limits` section (optional) allows you to adjust delays between API calls.
    
-   If no keys are provided, the script will still run in **offline-only mode**.
    

## 🔧 Usage

### Basic command:

`python Malware_Analyzer.py <path_to_file_or_directory>`

### Flags:

-   `--online, -o` → Enable online scans (VirusTotal, Hybrid-Analysis)
    
-   `--offline, -f` → Enable offline scans (hash, YARA, strings, PE)
    
-   `--report-format, -r` → Comma-separated list: `txt,html,pdf` or `none`
    

### Example (full scan with all reports):

`python Malware_Analyzer.py samples/malware.exe --online --offline --report-format txt,html,pdf`

### Example (offline-only, no reports saved):

`python Malware_Analyzer.py samples/ -f -r none`

### Interactive Mode (default if no flags provided):

If you run without flags, the tool will ask:

-   Whether to run online/offline scans
    
-   Which report formats to generate
    

## 📝 Output

-   **Indicators**
    
    -   VirusTotal detections
        
    -   Hybrid-Analysis threat score
        
    -   YARA matches
        
    -   MalwareBazaar match
        
-   **Details**
    
    -   Suspicious strings (sample)
        
    -   YARA rules triggered
        
    -   PE sections & suspicious imports
        
-   **Final Risk Score**
    
    -   Boxed, color-coded score with **LOW / MEDIUM / HIGH** label
        
-   **Reports**
    
    -   Saves TXT, HTML, and PDF reports alongside the scanned file
        

## 📂 Example Report (Summary)

`File: samples/malware.exe MD5: e99a18c428cb38d5f260853678922e03 SHA256: 2c26b46b68ffc68ff99b453c1d30413413422b4a4b8bdfab6e12e0a6f1b9e3e3  VirusTotal: 25 AV engines flagged (malicious) Hybrid-Analysis: Threat Score = 80, Verdict = malicious YARA hits: 3 Suspicious strings: powershell, http://malicious[.]com, rundll32  Final Risk Score: 100/100 (HIGH RISK)`

## ⚠️ Disclaimer

This tool is for **educational and defensive security purposes only**.  
Do **not** use it for offensive, malicious, or illegal activities.  
The author assumes **no liability** for misuse.
