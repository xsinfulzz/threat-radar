"""ZeroWare backend: forwards file fingerprints (and, with consent, files)
to VirusTotal, which runs 70+ real antivirus engines."""
import os
import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

load_dotenv()
KEY = os.getenv("VT_API_KEY", "").strip()
VT = "https://www.virustotal.com/api/v3"

app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 650 * 1024 * 1024  # VirusTotal's maximum file size


def vt(method, path, **kw):
    if not KEY:
        raise RuntimeError("VT_API_KEY is not set. Add it to a .env file (see README).")
    return requests.request(method, VT + path, headers={"x-apikey": KEY}, timeout=60, **kw)


def vt_error(r):
    msg = {
        401: "VirusTotal rejected the API key. Check VT_API_KEY in .env.",
        429: "VirusTotal rate limit reached. Free keys allow 4 requests per minute; wait a minute and retry.",
    }.get(r.status_code, f"VirusTotal returned an error ({r.status_code}).")
    return jsonify(error=msg), (r.status_code if r.status_code in (401, 429) else 502)


def pack(results, stats, attrs=None):
    attrs = attrs or {}
    engines = [
        {"engine": v.get("engine_name", k), "category": v.get("category", ""), "threat": v.get("result")}
        for k, v in results.items()
    ]
    engines.sort(key=lambda e: e["engine"].lower())
    return {
        "status": "done",
        "stats": stats,
        "engines": engines,
        "type": attrs.get("type_description"),
        "size": attrs.get("size"),
    }


@app.errorhandler(RuntimeError)
def runtime_error(e):
    return jsonify(error=str(e)), 500


@app.errorhandler(requests.RequestException)
def network_error(e):
    return jsonify(error="Could not reach VirusTotal. Check your internet connection."), 502


@app.errorhandler(413)
def too_big(e):
    return jsonify(error="File is over 650 MB, the VirusTotal maximum."), 413


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/lookup/<sha256>")
def lookup(sha256):
    """Hash-only lookup. The file itself never leaves the user's computer."""
    r = vt("GET", f"/files/{sha256}")
    if r.status_code == 404:
        return jsonify(status="unknown")
    if r.status_code != 200:
        return vt_error(r)
    a = r.json()["data"]["attributes"]
    return jsonify(pack(a.get("last_analysis_results", {}), a.get("last_analysis_stats", {}), a))


@app.post("/api/upload")
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify(error="No file received."), 400
    f.stream.seek(0, 2)
    size = f.stream.tell()
    f.stream.seek(0)
    if size > 32 * 1024 * 1024:
        # Files over 32 MB must go to a special one-time upload URL.
        u = vt("GET", "/files/upload_url")
        if u.status_code != 200:
            return vt_error(u)
        r = requests.post(u.json()["data"], headers={"x-apikey": KEY},
                          files={"file": (f.filename, f.stream)}, timeout=1800)
    else:
        r = vt("POST", "/files", files={"file": (f.filename, f.stream)})
    if r.status_code != 200:
        return vt_error(r)
    return jsonify(analysis_id=r.json()["data"]["id"])


@app.get("/api/analysis/<analysis_id>")
def analysis(analysis_id):
    r = vt("GET", f"/analyses/{analysis_id}")
    if r.status_code != 200:
        return vt_error(r)
    a = r.json()["data"]["attributes"]
    if a.get("status") != "completed":
        return jsonify(status="pending")
    return jsonify(pack(a.get("results", {}), a.get("stats", {})))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
