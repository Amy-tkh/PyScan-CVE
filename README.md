# 🛡️ PyScan-CVE: Multithreaded Vulnerability Scanner

A Python-based network security tool designed to automate the reconnaissance and initial vulnerability assessment phases of a penetration test.

## 🚀 Features
* **TCP Port Scanning:** Rapidly identifies open ports using the `socket` library.
* **Service Banner Grabbing:** Performs service identification by capturing response banners from open ports.
* **Automated CVE Lookup:** Integrates with the CIRCL CVE API to cross-reference identified services with known vulnerabilities.
* **Multithreaded Performance:** Utilizes Python's `threading` module to perform concurrent scans, significantly reducing execution time.
* **Automated Reporting:** Generates a structured `.txt` report of all findings for further analysis.

## 🛠️ Installation & Usage
1. **Clone the repository:**
   git clone https://github.com/Amy-tkh/PyScan-CVE/ 
   cd PyScan-CVE