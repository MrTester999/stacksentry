export function collectCatalogProperties(requiredPaths, root = globalThis) {
  const primitive = (value) => {
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value).slice(0, 500);
    return value == null ? "" : "true";
  };
  const readPath = (path) => {
    const parts = String(path).trim().split(".").filter(Boolean);
    let current = root;
    for (const part of parts) {
      if ((typeof current !== "object" && typeof current !== "function") || current === null) return "";
      let descriptor;
      try { descriptor = Object.getOwnPropertyDescriptor(current, part); }
      catch { return ""; }
      if (!descriptor || !("value" in descriptor)) return "";
      current = descriptor.value;
    }
    return primitive(current);
  };
  return Object.fromEntries(requiredPaths.map((path) => [path, readPath(path)]).filter(([, value]) => value));
}
