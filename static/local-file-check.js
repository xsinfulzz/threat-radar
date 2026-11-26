import { matchKnownMalware } from "./local-malware-hashes.js";

const EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const documentExtensions = new Set([
  "doc", "docx", "gif", "heic", "jpeg", "jpg", "mp3", "mp4", "pdf", "png",
  "ppt", "pptx", "rtf", "tiff", "txt", "webp", "xls", "xlsx", "zip",
]);
const runnableExtensions = new Set([
  "bat", "cmd", "com", "exe", "hta", "js", "jse", "lnk", "msi", "pif",
  "ps1", "scr", "vbe", "vbs", "wsf",
]);

async function hasWindowsExecutableHeader(file) {
  if (file.size < 64) return false;
  const dos = new DataView(await file.slice(0, 64).arrayBuffer());
  if (dos.byteLength !== 64 || dos.getUint16(0, true) !== 0x5a4d) return false;

  // Microsoft's PE/COFF format stores the header offset in e_lfanew.
  const offset = dos.getUint32(60, true);
  if (offset < 64 || offset + 26 > file.size) return false;
  const header = new DataView(await file.slice(offset, offset + 26).arrayBuffer());
  if (header.byteLength !== 26 || header.getUint32(0, true) !== 0x00004550) return false;

  const sections = header.getUint16(6, true);
  const optionalHeaderSize = header.getUint16(20, true);
  const executable = (header.getUint16(22, true) & 0x0002) !== 0;
  const magic = header.getUint16(24, true);
  const minimumHeaderSize = magic === 0x010b ? 96 : magic === 0x020b ? 112 : 0;
  const endOfSections = offset + 24 + optionalHeaderSize + sections * 40;
  return executable && sections > 0 && sections <= 96 && minimumHeaderSize > 0
    && optionalHeaderSize >= minimumHeaderSize && endOfSections <= file.size;
}

export async function checkLocalFile(file, sha256) {
  const matches = [];
  const indicators = [];
  const checks = [];
  const digest = typeof sha256 === "string" ? sha256.toLowerCase() : "";

  if (/^[a-f0-9]{64}$/.test(digest)) {
    checks.push("SHA-256 compared with the built-in signature list");
    if (file.size === 68 && digest === EICAR_SHA256) {
      matches.push({
        kind: "test",
        name: "EICAR antivirus test file",
        detail: "The fingerprint matches the harmless 68-byte EICAR test sample.",
      });
    } else {
      const signature = matchKnownMalware(digest);
      if (signature) matches.push(signature);
    }
  }

  checks.push("Filename checked for misleading extensions and text-direction overrides");
  if (/[\u202d\u202e]/u.test(file.name)) {
    indicators.push({
      name: "Filename can display in a misleading order",
      detail: "It contains a text-direction override that can change how its extension appears.",
    });
  }

  const parts = file.name.toLowerCase().replace(/[. ]+$/u, "").split(".");
  const extension = parts.length > 1 ? parts.at(-1) : "";
  if (parts.length >= 3 && runnableExtensions.has(extension) && documentExtensions.has(parts.at(-2).trim())) {
    indicators.push({
      name: "Document-like name with a runnable extension",
      detail: "The filename ends with a program, script, installer, or shortcut extension after a document or media extension.",
    });
  }

  if (documentExtensions.has(extension)) {
    const executableHeader = await hasWindowsExecutableHeader(file).catch(() => null);
    checks.push(executableHeader === null
      ? "File header could not be read"
      : "Document, media, or archive extension checked against the Windows executable header");
    if (executableHeader) {
      indicators.push({
        name: "Windows executable header under a misleading extension",
        detail: "The header identifies a Windows executable format despite the filename’s document, media, or archive extension.",
      });
    }
  }

  return { source: "local", status: "done", matches, indicators, checks };
}
