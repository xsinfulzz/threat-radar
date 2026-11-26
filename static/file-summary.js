import { describeThreat } from "./threat-labels.js";

const broadLabels = new Set([
  "General malware warning", "Unrecognised label", "Threat-intelligence match",
]);

export function engineKind(category) {
  if (category === "malicious" || category === "suspicious") return "threat";
  if (category === "undetected" || category === "harmless") return "clean";
  return "skip";
}

export function summarizeFileResults(engines) {
  let malicious = 0;
  let suspicious = 0;
  let clean = 0;
  let skipped = 0;
  let unclear = 0;
  let testLabels = 0;
  const classifications = new Map();
  const detections = [];
  const tags = new Set();

  for (const engine of engines) {
    const kind = engineKind(engine.category);
    if (kind === "skip") {
      skipped++;
      continue;
    }
    if (kind === "clean") {
      clean++;
      continue;
    }
    if (engine.category === "malicious") malicious++;
    else suspicious++;
    const label = String(engine.threat || "").trim();
    detections.push({ engine: engine.engine, category: engine.category, label });
    const info = describeThreat(label);
    for (const tag of info.tags) tags.add(tag);
    if (broadLabels.has(info.name)) {
      unclear++;
      continue;
    }
    if (info.name === "Test file (EICAR)") testLabels++;
    const group = classifications.get(info.name) ?? { ...info, count: 0 };
    group.count++;
    classifications.set(info.name, group);
  }

  return {
    malicious, suspicious, clean, skipped, unclear, testLabels, detections, tags: [...tags],
    classifications: [...classifications.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
  };
}
