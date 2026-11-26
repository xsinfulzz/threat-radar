import { describeThreat } from "./threat-labels.js";

const MB = 1024 * 1024;
const HASH_WASM_URL = "https://cdn.jsdelivr.net/npm/hash-wasm@4.11.0/dist/sha256.umd.min.js";
const pages = { scan: "Scan", results: "Results", docs: "Docs" };
const byId = id => document.getElementById(id);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
const completionHold = 900;
const minimumPresentation = 4000;

const fileInput = byId("file");
const dropzone = byId("dropzone");
const browse = byId("browse");
const retry = byId("choose-again");
const uploadDialog = byId("upload-dialog");
const steps = [...byId("steps").children];
const progress = byId("progress");
const track = byId("scan-track");
const filterButtons = [...byId("filters").querySelectorAll("button")];
const engineBody = byId("engines");
for (const id of ["scan-placeholder", "results-placeholder"]) {
  byId(id).append(byId("report-skeleton").content.cloneNode(true));
}
let busy = false;
let currentPage;
let report;
let filter = "all";
let hashLibrary;

function renderPage({ focus = false } = {}) {
  const requested = window.location.hash.slice(1);
  const page = Object.hasOwn(pages, requested) ? requested : "scan";
  if (page === currentPage) return;
  currentPage = page;
  for (const key of Object.keys(pages)) byId(key).hidden = key !== page;
  for (const link of document.querySelectorAll(".nav [data-page]")) {
    if (link.dataset.page === page) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  byId("path-label").textContent = pages[page];
  if (focus) byId(page + "-heading").focus();
}

window.addEventListener("hashchange", () => renderPage({ focus: true }));
document.querySelector(".skip-link").addEventListener("click", event => {
  event.preventDefault();
  byId("workspace").focus();
});
renderPage();

const themeButton = byId("theme");
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const label = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
  themeButton.setAttribute("aria-label", label);
  themeButton.title = label;
  themeButton.querySelector("use").setAttribute("href", theme === "dark" ? "#i-sun" : "#i-moon");
}
try {
  if (localStorage.getItem("zeroware-theme") === "light") applyTheme("light");
} catch { /* The theme can still be toggled when storage is unavailable. */ }
themeButton.addEventListener("click", () => {
  const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(theme);
  try { localStorage.setItem("zeroware-theme", theme); } catch { /* Optional preference. */ }
});

function setProgress(title, detail, stage, state = "working") {
  const active = state === "working" || state === "finishing";
  const complete = state === "complete";
  dropzone.hidden = true;
  progress.hidden = false;
  progress.dataset.state = state;
  retry.hidden = active || complete;
  byId("scan-count").textContent = (complete ? 1 : 0) + " of 1 file scanned";
  const status = byId("scan-status");
  if (status.textContent !== title) {
    const caption = document.createElement("span");
    caption.textContent = title;
    status.replaceChildren(caption);
  }
  byId("scan-detail").textContent = detail;
  byId("footer-status").textContent = title;
  track.hidden = !active && !complete;
  if (complete) track.setAttribute("aria-valuenow", "100");
  else track.removeAttribute("aria-valuenow");
  byId("scan-placeholder").hidden = !active;
  byId("results-placeholder").hidden = !active || Boolean(report);
  byId("results-empty").hidden = active || Boolean(report);
  for (const [index, step] of steps.entries()) {
    const stepState = complete || index < stage ? "done"
      : index !== stage ? "pending" : active ? "active" : "failed";
    step.dataset.state = stepState;
    step.firstElementChild.textContent = stepState === "done" ? "✓" : index + 1;
    if (stepState === "active") step.setAttribute("aria-current", "step");
    else step.removeAttribute("aria-current");
  }
}

function updateElapsed(start) {
  const seconds = Math.floor((performance.now() - start) / 1000);
  const time = byId("scan-elapsed");
  time.dateTime = "PT" + seconds + "S";
  const clock = [Math.floor(seconds / 60), seconds % 60].map(part => String(part).padStart(2, "0")).join(":");
  time.textContent = "Elapsed " + clock;
}

function fileSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < MB) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / MB).toFixed(1) + " MB";
}

function visibleMotion() {
  return currentPage === "scan" && !document.hidden && !reducedMotion.matches;
}

function loadHashLibrary() {
  hashLibrary ??= new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = HASH_WASM_URL;
    script.onload = () => {
      if (typeof window.hashwasm?.createSHA256 === "function") resolve(window.hashwasm);
      else {
        script.remove();
        reject(new Error("The file fingerprint tool could not initialize. Try again."));
      }
    };
    script.onerror = () => {
      script.remove();
      reject(new Error("The file fingerprint tool could not load. Check your connection and try again."));
    };
    document.head.append(script);
  }).catch(error => {
    hashLibrary = undefined;
    throw error;
  });
  return hashLibrary;
}

async function sha256(file, startHash) {
  if (file.size <= 100 * MB && window.crypto?.subtle) {
    const data = await file.arrayBuffer();
    startHash();
    const digest = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
  }
  const library = await loadHashLibrary();
  const hash = await library.createSHA256();
  hash.init();
  startHash();
  const chunkSize = 8 * MB;
  for (let offset = 0; offset < file.size; offset += chunkSize) {
    hash.update(new Uint8Array(await file.slice(offset, offset + chunkSize).arrayBuffer()));
    byId("scan-detail").textContent = file.name + " (" + Math.round(Math.min(offset + chunkSize, file.size) / file.size * 100) + "%)";
  }
  return hash.digest();
}

async function api(path, options) {
  let response;
  try { response = await fetch(path, options); }
  catch { throw new Error("Could not reach the ZeroWare server. Check your connection and try again."); }
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error || "Server request failed (" + response.status + ").");
  if (!body || typeof body !== "object") throw new Error("The server returned an unreadable response. Try again.");
  return body;
}

function askToUpload(file) {
  byId("upload-name").textContent = file.name;
  uploadDialog.returnValue = "cancel";
  return new Promise(resolve => {
    uploadDialog.addEventListener("close", () => resolve(uploadDialog.returnValue === "upload"), { once: true });
    uploadDialog.showModal();
  });
}

async function runScan(file) {
  if (!file || busy) return;
  busy = true;
  browse.disabled = true;
  const started = performance.now();
  byId("scan-size").textContent = fileSize(file.size);
  updateElapsed(started);
  const elapsedTimer = setInterval(() => updateElapsed(started), 1000);
  let stage = 0;
  try {
    if (file.size > 650 * MB) throw new Error("Choose a file that is 650 MB or smaller.");
    setProgress("Reading file", file.name, stage);
    if (visibleMotion()) await delay(180);
    const hash = await sha256(file, () => {
      stage = 1;
      setProgress("Checking the file hash", file.name, stage);
    });
    if (visibleMotion()) await delay(180);
    stage = 2;
    setProgress("Checking VirusTotal", file.name, stage);
    let result = await api("/api/lookup/" + hash);
    if (result.status === "unknown") {
      setProgress("Waiting for upload decision", file.name, stage);
      if (!await askToUpload(file)) {
        setProgress("Scan cancelled", "The file was not uploaded.", stage, "cancelled");
        return;
      }
      setProgress("Uploading file…", file.name, stage);
      const form = new FormData();
      form.append("file", file);
      const upload = await api("/api/upload", { method: "POST", body: form });
      if (typeof upload.analysis_id !== "string" || !upload.analysis_id) throw new Error("VirusTotal did not return a scan ID.");
      stage = 3;
      setProgress("Analyzing file", file.name, stage);
      for (let attempt = 0; attempt < 60; attempt++) {
        await delay(3000);
        result = await api("/api/analysis/" + encodeURIComponent(upload.analysis_id));
        if (result.status === "done") break;
        if (result.status !== "pending") throw new Error("VirusTotal returned an unexpected scan status.");
      }
      if (result.status === "pending") throw new Error("The analysis is taking longer than expected. Try a new lookup in a minute.");
    }
    if (result.status !== "done" || !Array.isArray(result.engines)) throw new Error("The server did not return an engine report.");
    if (stage === 2 && visibleMotion()) await delay(220);
    stage = 3;
    setProgress("Finishing up", file.name, stage, "finishing");
    if (visibleMotion()) {
      const remaining = minimumPresentation - completionHold - (performance.now() - started);
      await delay(Math.max(420, remaining));
    }
    setProgress("Complete", file.name, stage, "complete");
    clearInterval(elapsedTimer);
    updateElapsed(started);
    if (visibleMotion()) await delay(completionHold);
    renderReport(result, file.name, hash);
    if (currentPage === "scan") location.hash = "results";
  } catch (error) {
    setProgress("Scan failed", error.message, stage, "failed");
  } finally {
    clearInterval(elapsedTimer);
    if (progress.dataset.state !== "complete") updateElapsed(started);
    busy = false;
    browse.disabled = false;
    if (progress.dataset.state === "complete") {
      progress.hidden = true;
      dropzone.hidden = false;
    }
  }
}

browse.addEventListener("click", () => fileInput.click());
retry.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  const [file] = fileInput.files;
  fileInput.value = "";
  void runScan(file);
});
const scanPanel = dropzone.closest(".scan-panel");
scanPanel.addEventListener("dragover", event => {
  if (!event.dataTransfer.types.includes("Files")) return;
  event.preventDefault();
  event.dataTransfer.dropEffect = busy ? "none" : "copy";
  if (!busy) (progress.hidden ? dropzone : progress).dataset.dragover = "";
});
function clearDrag() {
  delete dropzone.dataset.dragover;
  delete progress.dataset.dragover;
}
scanPanel.addEventListener("dragleave", event => {
  if (!scanPanel.contains(event.relatedTarget)) clearDrag();
});
scanPanel.addEventListener("drop", event => {
  event.preventDefault();
  clearDrag();
  void runScan(event.dataTransfer.files[0]);
});

function engineKind(category) {
  if (category === "malicious" || category === "suspicious") return "threat";
  if (category === "undetected" || category === "harmless") return "clean";
  return "skip";
}

function renderReport(result, fileName, hash) {
  const malicious = result.engines.filter(engine => engine.category === "malicious").length;
  const flagged = result.engines.filter(engine => engineKind(engine.category) === "threat").length;
  const clean = result.engines.filter(engine => engineKind(engine.category) === "clean").length;
  const verdict = byId("verdict");
  if (flagged > 0) {
    verdict.dataset.tone = "flagged";
    byId("verdict-title").textContent = malicious >= 3 ? "Malicious" : "Flagged";
    byId("verdict-detail").textContent = flagged + " of " + (flagged + clean) + " engines that returned a verdict flagged this file.";
  } else if (clean > 0) {
    verdict.dataset.tone = "clean";
    byId("verdict-title").textContent = "No threats detected";
    byId("verdict-detail").textContent = "The reporting engines did not flag this file. Review its source before opening it.";
  } else {
    verdict.dataset.tone = "unknown";
    byId("verdict-title").textContent = "No verdict";
    byId("verdict-detail").textContent = "No engine returned a usable verdict for this file.";
  }
  report = { engines: result.engines, flagged, total: flagged + clean };
  byId("report-file").textContent = fileName;
  byId("report-hash").textContent = hash;
  byId("flagged-count").textContent = flagged;
  byId("clean-count").textContent = clean;
  byId("skipped-count").textContent = result.engines.length - flagged - clean;
  byId("results-empty").hidden = true;
  byId("report").hidden = false;
  filter = flagged ? "threat" : "all";
  renderEngines();
}

function renderEngines() {
  for (const button of filterButtons) button.setAttribute("aria-pressed", String(button.dataset.filter === filter));
  const fragment = document.createDocumentFragment();
  const engines = report.engines.filter(engine => filter === "all" || engineKind(engine.category) === filter);
  for (const engine of engines) {
    const kind = engineKind(engine.category);
    const row = document.createElement("tr");
    const name = document.createElement("th");
    name.scope = "row";
    name.textContent = engine.engine;
    const verdict = document.createElement("td");
    verdict.className = "tone-" + kind;
    verdict.textContent = kind === "threat" ? (engine.threat || engine.category) : kind === "clean" ? "Clean" : "Not scanned";
    const actions = document.createElement("td");
    if (kind === "threat") {
      const learn = document.createElement("button");
      learn.type = "button";
      learn.className = "button learn-more";
      learn.textContent = "Learn more";
      learn.setAttribute("aria-label", "Learn more about " + engine.engine + "'s detection");
      learn.addEventListener("click", () => showThreat(engine));
      actions.append(learn);
    }
    row.append(name, verdict, actions);
    fragment.append(row);
  }
  engineBody.replaceChildren(fragment);
  byId("engine-empty").hidden = engines.length > 0;
}

for (const button of filterButtons) button.addEventListener("click", () => {
  if (!report) return;
  filter = button.dataset.filter;
  renderEngines();
});

function showThreat(engine) {
  const label = String(engine.threat || engine.category);
  const info = describeThreat(label);
  const details = byId("threat-details");
  byId("threat-title").textContent = info.name;
  const source = document.createElement("p");
  source.textContent = engine.engine + " · " + label + " · " + (info.risk === "Unclear" ? "Risk unclear" : info.risk + " risk");
  details.replaceChildren(source);
  for (const [heading, message] of [
    ["What the label generally means", info.meaning],
    ["Potential impact", info.impact],
    ["What to do", info.advice],
    ["Naming hints", info.tags.join(" · ")],
  ]) {
    if (!message) continue;
    const title = document.createElement("h3");
    title.textContent = heading;
    const body = document.createElement("p");
    body.textContent = message;
    details.append(title, body);
  }
  const note = document.createElement("p");
  note.textContent = report.flagged + " of " + report.total + " reporting engines flagged this file. Engine labels alone can’t confirm how a file behaves.";
  details.append(note);
  byId("threat-dialog").showModal();
}
