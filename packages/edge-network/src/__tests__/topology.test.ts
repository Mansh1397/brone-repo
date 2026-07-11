import * as fs from "fs";
import * as path from "path";

// A clean, state-based TOML fallback parser to satisfy workspace parser enforcement
function parseTOML(text: string): any {
  const result: any = {};
  let currentSection = result;
  
  // Join multi-line arrays by converting newlines inside brackets to spaces
  let normalizedText = text.replace(/\[\s*([^\]]+?)\s*\]/g, (match, p1) => {
    if (!p1.includes("=") && !p1.includes(",")) return match;
    return "[" + p1.replace(/\s+/g, " ") + "]";
  });

  const lines = normalizedText.split("\n");
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;

    if (line.startsWith("[") && line.endsWith("]")) {
      const sectionName = line.slice(1, -1).trim();
      const parts = sectionName.split(".");
      currentSection = result;
      for (const part of parts) {
        if (!currentSection[part]) {
          currentSection[part] = {};
        }
        currentSection = currentSection[part];
      }
    } else {
      const idx = line.indexOf("=");
      if (idx !== -1) {
        const key = line.slice(0, idx).trim();
        let val = line.slice(idx + 1).trim();

        if (val.startsWith('"') && val.endsWith('"')) {
          val = val.slice(1, -1);
        } else if (val.startsWith("[") && val.endsWith("]")) {
          const arrayStr = val.slice(1, -1).trim();
          if (arrayStr.includes("{")) {
            const items = [];
            const objRegex = /\{([^}]+)\}/g;
            let match;
            while ((match = objRegex.exec(arrayStr)) !== null) {
              const obj: any = {};
              const pairs = match[1].split(",");
              for (const pair of pairs) {
                const eqIdx = pair.indexOf("=");
                if (eqIdx !== -1) {
                  const k = pair.slice(0, eqIdx).trim();
                  let v = pair.slice(eqIdx + 1).trim();
                  if (v.startsWith('"') && v.endsWith('"')) {
                    v = v.slice(1, -1);
                  }
                  obj[k] = v;
                }
              }
              items.push(obj);
            }
            currentSection[key] = items;
            continue;
          } else {
            currentSection[key] = arrayStr.split(",").map((item) => {
              let cleaned = item.trim();
              if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
                cleaned = cleaned.slice(1, -1);
              }
              return cleaned;
            });
            continue;
          }
        }
        currentSection[key] = val;
      }
    }
  }
  return result;
}

describe("Wrangler Topology Configuration Validation", () => {
  let config: any;

  beforeAll(() => {
    const tomlPath = path.resolve(__dirname, "../../wrangler.toml");
    const tomlText = fs.readFileSync(tomlPath, "utf8");
    config = parseTOML(tomlText);
  });

  it("should successfully resolve main entry point to src/ipMasker.ts", () => {
    expect(config.main).toBe("src/ipMasker.ts");
  });

  it("should contain exactly the two target transactional routing paths with correct zone names", () => {
    expect(config.routes).toBeDefined();
    expect(Array.isArray(config.routes)).toBe(true);
    expect(config.routes.length).toBe(2);

    expect(config.routes[0]).toEqual({
      pattern: "api.brone.network/api/v1/verify",
      zone_name: "brone.network"
    });

    expect(config.routes[1]).toEqual({
      pattern: "api.brone.network/api/v1/stamp",
      zone_name: "brone.network"
    });
  });

  it("should strictly evaluate NODE_ENV under the production environment definition vars structure", () => {
    expect(config.env).toBeDefined();
    expect(config.env.production).toBeDefined();
    expect(config.env.production.vars).toBeDefined();
    expect(config.env.production.vars.NODE_ENV).toBe("production");
  });

  it("should assert that no hardcoded secret keys, 64-char hex strings, or private key artifacts exist in wrangler.toml", () => {
    const scanForSecrets = (obj: any) => {
      if (typeof obj === "string") {
        // Hex pattern search for raw 256-bit keys (64 characters)
        expect(/^[a-fA-F0-9]{64}$/.test(obj)).toBe(false);
        // Sensitive keyword search
        expect(obj.includes("PRIVATE KEY")).toBe(false);
        expect(obj.includes("BEGIN RSA PRIVATE KEY")).toBe(false);
      } else if (typeof obj === "object" && obj !== null) {
        for (const key of Object.keys(obj)) {
          scanForSecrets(obj[key]);
        }
      }
    };

    scanForSecrets(config);
  });
});
