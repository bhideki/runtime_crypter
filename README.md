# Runtime Crypter

A lightweight Python runtime crypter that obfuscates and packages payloads into standalone executables — includes an AMSI Bypass variation for enhanced runtime execution.

---

## Table of Contents
1. [Usage](#usage)  
2. [Notes](#notes)  
3. [Compile](#compile)  
4. [Requirements](#requirements)  
5. [Credits](#credits)  
6. [Disclaimer](#disclaimer)

---

## Usage
Run one of the following scripts using Python:

```bash
python runtime_crypter <payload_path> <output_stub_path>

python runtime_crypter_amsi_bypass <payload_path> <output_stub_path>
```

<payload_path> → Path to your raw executable payload (.bin)

<output_stub_path> → Desired path for the generated stub/executable

#Notes

Only raw executable files (.bin) are supported as payloads.

The AMSI Bypass version is based on the implementation in d0rb/AMSI-Bypass.

#Compile

After generating the stub script (output.py), compile it into a standalone executable using PyInstaller:
```bash
pyinstaller --noconsole --onefile output.py
```
#Requirements

Make sure the following dependencies are installed:

pyinstaller

pycryptodome

Install them with pip:

```bash
pip install pyinstaller pycryptodome
```

#Credits

AMSI Bypass implementation referenced from: [d0rb/AMSI-Bypass](https://github.com/d0rb/AMSI-Bypass)

# Disclaimer

This project is for educational purposes only.
The author does not take responsibility for any misuse of this tool.
Use only in controlled and legal environments.
