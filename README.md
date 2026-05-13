Project Title: Hybrid subdomain Enumeration Tool

Technology: Python

Project Description:
This project is a lightweight hybrid subdomain enumeration tool developed in
Python. It combines brute-force enumeration, search engine based discovery,
and certificate transparency techniques to identify subdomains of a target
domain. All discovered subdomains are validated using DNS resolution.

Features:
- Brute-force subdomain enumeration
- Search engine based enumeration
- Certificate Transparency (crt.sh) integration
- DNS resolution and validation
- Logging of successful and failed queries
- Lightweight and safe implementation

How to Run:
1. Install Python 3.x
2. Install dependencies:
   pip install -r requirements.txt
3. Execute the tool:
   python subdomain.py mdu.ac.in

Output:
- Valid subdomains are displayed on the terminal
- Results are stored in output files
- Execution logs are maintained using the logging module

Note:
This project is developed strictly for educational and academic purposes.
