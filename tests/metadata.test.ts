import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

function readJson(path: string): any {
  return JSON.parse(readFileSync(resolve(process.cwd(), path), "utf8"));
}

describe("release metadata", () => {
  const pkg = readJson("package.json");
  const server = readJson("server.json");
  const manifest = readJson("manifest.json");
  const serverSource = readFileSync(resolve(process.cwd(), "src/index.ts"), "utf8");

  it("keeps release versions aligned", () => {
    expect(server.version).toBe(pkg.version);
    expect(server.packages[0].version).toBe(pkg.version);
    expect(manifest.version).toBe(pkg.version);
    expect(serverSource).toContain(`const VERSION = "${pkg.version}";`);
  });

  it("keeps npm and MCP Registry identities aligned", () => {
    expect(server.name).toBe(pkg.mcpName);
    expect(server.packages[0].identifier).toBe(pkg.name);
    expect(server.packages[0].registryType).toBe("npm");
    expect(server.packages[0].transport.type).toBe("stdio");
  });

  it("satisfies current MCP Registry metadata limits", () => {
    expect(server.description.length).toBeLessThanOrEqual(100);
    expect(server.description.length).toBeGreaterThan(0);
  });

  it("declares all eight public tools", () => {
    const names = manifest.tools.map((tool: { name: string }) => tool.name);
    expect(names).toHaveLength(8);
    expect(names).toContain("assess_cloud_change_bundle");
    expect(new Set(names).size).toBe(names.length);
  });
});
