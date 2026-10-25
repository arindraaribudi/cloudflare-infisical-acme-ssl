import { describe, it, expect } from "vitest";
import { loadConfig, defaultPaths, validateConfig } from "../../src/lib/config";

describe("config", () => {
  it("applies defaults when fields are missing", () => {
    const cfg = validateConfig({
      apexes: ["example.com"],
      acmeEnv: "production",
      cloudflare: {
        zoneIdsByDomain: { "example.com": "zone-id-1" },
      },
      paths: { cert: "certs/<domain>", account: "ACME_ACCOUNT", status: "STATUS_LAST_RUN" },
    });
    expect(cfg.renewWithinDays).toBe(30);
  });

  it("rejects empty apexes", () => {
    expect(() =>
      validateConfig({
        apexes: [],
        acmeEnv: "production",
        cloudflare: { zoneIdsByDomain: {} },
        paths: { cert: "certs/<domain>", account: "ACME_ACCOUNT", status: "STATUS_LAST_RUN" },
      }),
    ).toThrow(/apexes/);
  });

  it("rejects unknown acmeEnv", () => {
    expect(() =>
      validateConfig({
        apexes: ["example.com"],
        acmeEnv: "test",
        cloudflare: { zoneIdsByDomain: { "example.com": "z" } },
        paths: { cert: "certs/<domain>", account: "ACME_ACCOUNT", status: "STATUS_LAST_RUN" },
      }),
    ).toThrow(/acmeEnv/);
  });

  it("rejects missing zoneId for an apex", () => {
    expect(() =>
      validateConfig({
        apexes: ["example.com", "missing.com"],
        acmeEnv: "production",
        cloudflare: { zoneIdsByDomain: { "example.com": "z" } },
        paths: { cert: "certs/<domain>", account: "ACME_ACCOUNT", status: "STATUS_LAST_RUN" },
      }),
    ).toThrow(/missing.com/);
  });

  it("substitutes <domain> in cert path", () => {
    const paths = defaultPaths();
    const apex = "example.com";
    const out = paths.cert.replace("<domain>", apex);
    expect(out).toBe("certs/example.com");
  });

  it("loadConfig parses JSON string", async () => {
    const json = JSON.stringify({
      apexes: ["example.com"],
      acmeEnv: "staging",
      cloudflare: { zoneIdsByDomain: { "example.com": "z" } },
      paths: { cert: "certs/<domain>", account: "ACME_ACCOUNT", status: "STATUS_LAST_RUN" },
    });
    const cfg = await loadConfig(json);
    expect(cfg.acmeEnv).toBe("staging");
  });
});