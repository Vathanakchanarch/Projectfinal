<<<<<<< HEAD
# Threat Hunter 🛡️

**Threat Hunter** is a Python-based malware detection and quarantine tool. It scans files and folders for known malware, allows you to quarantine infected files, and safely remove viruses from your system.

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Contact](#contact)

---

## Features
- Scan files and directories for malware using SHA-256 hash comparison.
- Quarantine infected files into a password-protected ZIP archive.
- Remove specific or all quarantined files with authentication.
- Display scan results including total files scanned and detected malware.
- User-friendly console interface with colorful output.

---

## Installation
1. Clone the repository:
```bash
git clone https://github.com/Vathanakchanarch/Projectfinal
pip install colorama pyfiglet

Set the database paths in core/setting.py:
virusHash.txt – contains SHA-256 hashes of known malware.
virusInfo.txt – contains malware names corresponding to hashes.
Set the path Quanrantine.zip in core/Quanrantine.py 


## Usage
Run the main program:
You will see a menu:
Scan file – Scan a file or folder for malware.
Quarantine – Move detected malware to a password-protected ZIP.
Remove Virus – Remove specific or all quarantined files with password authentication.
Exit – Exit the program.

## Project Structure
project/
│
├── core/
│   ├── analyzer.py        # Scanning functionality
│   ├── Quanratine.py     # Quarantine functionality
│   ├── Removevirus.py    # Removing viruses from quarantine
│   └── setting.py        # MalwareDetection base class & utility functions
├── database/
│   ├── virusHash.txt     # SHA-256 hashes of known malware
│   └── virusInfo.txt     # Corresponding malware names
├── VirusFile/
│   ├── eicar-com.com       #These all virus for Testing
│   ├── eicar-test.txt     
│   ├── eicar-zip.zip    
│   └── keylogger.zip
│  
├── main.py               # Main program entry point
└── README.md             # This file

## Contact
Chan Archvathanak – vathanak4634@gmail.com
Project Link: https://github.com/Vathanakchanarch/Projectfinal

>>>>>>> b1f231e179fd4c4e6ef2898696a16fd89b794024
