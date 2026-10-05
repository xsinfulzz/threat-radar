# Threat Radar

A school-project file scanner. The browser fingerprints your file (SHA-256) and a small
Flask server asks VirusTotal, which runs 70+ real antivirus engines, what they think of it.

## Setup
1. Install Python 3.9+ from python.org.
2. Create a free account at https://www.virustotal.com and copy your API key
   (profile menu > API key).
3. In this folder:
   ```
   pip install -r requirements.txt
   copy .env.example .env        (Mac/Linux: cp .env.example .env)
   ```
   Open `.env` and paste your key after `VT_API_KEY=`.
4. Run `python app.py` and open http://127.0.0.1:5000

## Notes
- Free keys: 4 requests/minute, 500/day. Fine for a class demo.
- Known files are checked by hash only; nothing is uploaded. Unknown files are uploaded
  only if you click "Upload and scan". VirusTotal shares uploads with security companies,
  so never upload personal or private files.
- Max upload: 32 MB.
- Test safely with the EICAR file from https://www.eicar.org (harmless, flagged by design).
