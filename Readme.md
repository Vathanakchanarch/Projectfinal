# Threat Hunter 🛡️

**Threat Hunter** is a Python-based malware detection and quarantine tool. It scans files and folders for known malware, allows you to quarantine infected files, and safely remove viruses from your system.

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [Project Structure](#project-structure)
* [Contact](#contact)

---

## Features

* Scan files and directories for malware using SHA-256 hash comparison.
* Quarantine infected files into a password-protected ZIP archive.
* Remove specific or all quarantined files with authentication.
* Display scan results including total files scanned and detected malware.
* User-friendly console interface with colorful output.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Vathanakchanarch/Projectfinal
cd Projectfinal
```

2. Install dependencies:

```bash
pip install colorama pyfiglet
```

3. Configure paths:

* In `core/setting.py`, set the database paths:

  * `virusHash.txt` – contains SHA-256 hashes of known malware
  * `virusInfo.txt` – contains malware names corresponding to the hashes
* In `core/Quanrantine.py`, set the path for `Quarantine.zip`

---

## Usage

Run the main program:

```bash
python main.py
```

You will see a menu with the following options:

* **Scan File** – Scan a file or folder for malware
* **Quarantine** – Move detected malware to a password-protected ZIP archive
* **Remove Virus** – Remove specific or all quarantined files with password authentication
* **Exit** – Exit the program

---

## Project Structure

```
project/
│
├── core/
│   ├── analyzer.py        # Scanning functionality
│   ├── Quanratine.py      # Quarantine functionality
│   ├── Removevirus.py     # Remove viruses from quarantine
│   └── setting.py         # Malware detection base class & utility functions
│
├── database/
│   ├── virusHash.txt      # SHA-256 hashes of known malware
│   └── virusInfo.txt      # Corresponding malware names
│
├── VirusFile/
│   ├── eicar-com.com      # Test virus files
│   ├── eicar-test.txt
│   ├── eicar-zip.zip
│   └── keylogger.zip
│
├── main.py                # Main program entry point
└── README.md              # Project documentation
```

---

## Contact

**Chan Archvathanak**
📧 Email: [vathanak4634@gmail.com](mailto:vathanak4634@gmail.com)
🔗 Project Link: [https://github.com/Vathanakchanarch/Projectfinal](https://github.com/Vathanakchanarch/Projectfinal)
