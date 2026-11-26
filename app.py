"""ZeroWare relays file and public URL checks to VirusTotal."""
import base64
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

load_dotenv()
KEY = os.getenv("VT_API_KEY", "").strip()
VT = "https://www.virustotal.com/api/v3"

app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 650 * 1024 * 1024  # VirusTotal's maximum file size


def vt(method, path, *, timeout=60, **kw):
    if not KEY:
        raise RuntimeError("VT_API_KEY is not set. Add it to a .env file (see README).")
    return requests.request(method, VT + path, headers={"x-apikey": KEY}, timeout=timeout, **kw)


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


def public_web_url(value):
    """Normalize only HTTP(S) URLs. Never connect to or resolve the submitted host."""
    if not isinstance(value, str):
        raise ValueError("Enter a public website URL or domain.")
    value = value.strip()
    if not value or len(value.encode("utf-8")) > 2048 or re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise ValueError("Enter a valid website address of up to 2,048 characters.")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    host = (parts.hostname or "").rstrip(".").lower()
    if parts.scheme not in ("http", "https") or not host or parts.username is not None:
        raise ValueError("Use an HTTP or HTTPS address without embedded credentials.")
    if "%" in host:
        raise ValueError("Enter a valid public website address.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        host = host.encode("idna").decode("ascii")
        labels = host.split(".")
        private_suffixes = {"localhost", "local", "internal", "lan", "home", "test", "invalid", "example", "onion", "arpa", "localdomain"}
        valid_labels = all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
        if len(host) > 253 or len(labels) < 2 or not valid_labels or not labels[-1][0].isalpha() or labels[-1] in private_suffixes:
            raise ValueError("Enter a public website domain.")
        authority = host
    else:
        if not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError("Private and special-purpose addresses cannot be scanned.")
        authority = f"[{address}]" if address.version == 6 else str(address)
    if parts.port is not None:
        authority += f":{parts.port}"
    # Fragments do not identify the resource sent to the server and may contain tokens.
    return urlunsplit((parts.scheme, authority, parts.path or "/", parts.query, ""))


@app.post("/api/url/check")
def check_url():
    if not request.is_json:
        return jsonify(error="Send a JSON URL check request."), 415
    data = request.stream.read(8193)
    if len(data) > 8192:
        return jsonify(error="The URL request is too large."), 413
    try:
        body = json.loads(data)
    except (UnicodeError, ValueError):
        return jsonify(error="The URL request could not be read."), 400
    if not isinstance(body, dict) or body.get("share") is not True:
        return jsonify(error="Confirm sharing the address with VirusTotal first."), 400
    try:
        url = public_web_url(body.get("url"))
    except (ValueError, UnicodeError):
        return jsonify(error="Enter a valid public HTTP or HTTPS address without credentials."), 400

    identifier = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    provider_options = {"timeout": 20, "allow_redirects": False}
    existing = vt("GET", f"/urls/{identifier}", **provider_options)
    if existing.status_code == 200:
        attributes = existing.json()["data"]["attributes"]
        results = attributes.get("last_analysis_results") or {}
        if results:
            return jsonify(**pack(results, attributes.get("last_analysis_stats", {})), url=url)
    elif existing.status_code != 404:
        return vt_error(existing)

    submitted = vt("POST", "/urls", data={"url": url}, **provider_options)
    if submitted.status_code not in (200, 201, 202):
        return vt_error(submitted)
    analysis_id = submitted.json()["data"]["id"]
    if not valid_analysis_id(analysis_id):
        return jsonify(error="VirusTotal did not return a usable analysis ID."), 502
    return jsonify(status="pending", analysis_id=analysis_id, url=url)


def valid_analysis_id(value):
    return isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9_=-]{1,240}", value) is not None


@app.get("/api/analysis/<analysis_id>")
def analysis(analysis_id):
    if not valid_analysis_id(analysis_id):
        return jsonify(error="Invalid analysis ID."), 400
    r = vt("GET", f"/analyses/{analysis_id}", allow_redirects=False)
    if r.status_code != 200:
        return vt_error(r)
    a = r.json()["data"]["attributes"]
    if a.get("status") != "completed":
        return jsonify(status="pending")
    return jsonify(pack(a.get("results", {}), a.get("stats", {})))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
