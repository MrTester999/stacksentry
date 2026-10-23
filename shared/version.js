export function isExactVersion(value) {
  return /^\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?$/.test(String(value || "").trim());
}
