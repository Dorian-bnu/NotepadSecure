## Security Notice

This tool uses password-based encryption (PBKDF2 + Fernet/AES).
No password recovery is possible. If you lose your password, your data is permanently lost.

This software is provided "as is" without any warranty. Use at your own risk.


## Build the Windows executable

This project can be packaged as a standalone Windows executable using **PyInstaller**.

### Requirements

- Python 3.11+
- pip

Install dependencies:

```bash
pip install --upgrade pip
pip install pyinstaller cryptography

From the project directory containing main.py:

pyinstaller --onefile --windowed --name NotepadSecure --icon favicon.ico --add-data "favicon.ico;." main.py

The executable will be generated in:
dist/NotepadSecure.exe