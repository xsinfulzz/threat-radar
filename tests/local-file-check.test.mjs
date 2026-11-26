import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { checkLocalFile } from "../static/local-file-check.js";
import { matchKnownMalware } from "../static/local-malware-hashes.js";

test("every catalog entry is a unique, valid fingerprint with a source", async () => {
  const catalog = await readFile(new URL("../static/local-malware-hashes.js", import.meta.url), "utf8");
  const hashes = Array.from(catalog.matchAll(/"([a-f0-9]{60,68})"/g), match => match[1]);
  assert.ok(hashes.length > 1);
  assert.equal(new Set(hashes).size, hashes.length);
  for (const hash of hashes) {
    assert.match(hash, /^[a-f0-9]{64}$/);
    const signature = matchKnownMalware(hash);
    assert.equal(signature.kind, "malware");
    assert.match(signature.url, /^https:\/\//);
  }
});

test("exact malware and harmless antivirus test signatures stay distinct", async () => {
  // Substitute a digest for each test. The file contents are harmless fixtures.
  const rhysida = "6633fa85bb234a75927b23417313e51a4c155e12f71da3959e168851a600b010";
  const eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
  const malware = await checkLocalFile(new File(["fixture"], "example.bin"), rhysida);
  assert.equal(malware.matches[0].kind, "malware");
  const sample = await checkLocalFile(new File([new Uint8Array(68)], "sample.bin"), eicar);
  assert.equal(sample.matches[0].kind, "test");
  const wrongSize = await checkLocalFile(new File(["fixture"], "sample.bin"), eicar);
  assert.deepEqual(wrongSize.matches, []);
});

test("a normal document or executable does not trigger disguise warnings", async () => {
  for (const name of ["report.pdf", "report.final.pdf", "installer.exe"]) {
    const report = await checkLocalFile(new File([new Uint8Array(80)], name), "a".repeat(64));
    assert.deepEqual(report.matches, []);
    assert.deepEqual(report.indicators, []);
  }
});

test("double extensions and direction overrides produce warning signs only", async () => {
  const report = await checkLocalFile(new File(["fixture"], "notice\u202e.pdf.EXE"));
  assert.deepEqual(report.matches, []);
  assert.equal(report.indicators.length, 2);
});

test("an executable header under a document extension triggers a warning", async () => {
  // Populate only the PE fields checked by the detector. This is not runnable.
  const bytes = new Uint8Array(128 + 24 + 112 + 40);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x5a4d, true);
  view.setUint32(60, 128, true);
  view.setUint32(128, 0x00004550, true);
  view.setUint16(134, 1, true);
  view.setUint16(148, 112, true);
  view.setUint16(150, 0x0002, true);
  view.setUint16(152, 0x020b, true);
  const disguised = await checkLocalFile(new File([bytes], "image.png"));
  assert.equal(disguised.indicators.length, 1);
  assert.match(disguised.indicators[0].name, /Windows executable header/);
  const truncated = await checkLocalFile(new File([bytes.slice(0, 154)], "image.png"));
  assert.deepEqual(truncated.indicators, []);
});

test("an unreadable header does not erase a filename warning", async () => {
  const file = {
    name: "notice\u202e.pdf",
    size: 80,
    slice() { throw new Error("Fixture read error"); },
  };
  const report = await checkLocalFile(file);
  assert.ok(report.checks.includes("File header could not be read"));
  assert.equal(report.indicators.length, 1);
});
