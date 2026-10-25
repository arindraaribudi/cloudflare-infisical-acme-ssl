import { describe, it, expect, vi } from "vitest";
import { InfisicalClient } from "../../src/lib/infisical";
import { readCertBundle, writeCertBundle } from "../../src/lib/cert-store";
import type { CertBundle } from "../../src/lib/acme";

const LEAF_PEM = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n";
const INTER_PEM = "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n";
const KEY_PEM = "-----BEGIN PRIVATE KEY-----\nsecretkey\n-----END PRIVATE KEY-----\n";

const BUNDLE: CertBundle = {
  apex: "example.com",
  notAfter: "2026-12-01T00:00:00.000Z",
  issuedAt: "2026-09-01T00:00:00.000Z",
  acmeEnv: "production",
  fullchain: `${LEAF_PEM}${INTER_PEM}`,
  privateKey: KEY_PEM,
  chain: INTER_PEM,
};

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("cert-store", () => {
  const baseUrl = "https://app.infisical.com";
  const token = "service-token";
  const target = { token, projectId: "proj", env: "prod" };

  function makeClient(fetchMock: unknown): InfisicalClient {
    return new InfisicalClient({ baseUrl, fetch: fetchMock as unknown as typeof fetch });
  }

  function callOf(fetchMock: { mock: { calls: unknown[][] } }, index: number): [string, RequestInit] {
    return fetchMock.mock.calls[index]! as unknown as [string, RequestInit];
  }

  function bodyOf(call: [string, RequestInit]): Record<string, string> {
    return JSON.parse(call[1].body as string) as Record<string, string>;
  }

  describe("writeCertBundle", () => {
    it("upserts ONE secret holding the whole bundle as JSON", async () => {
      const fetchMock = vi.fn(async () => jsonResponse({}));
      const client = makeClient(fetchMock);

      await writeCertBundle(client, target, "certs/example.com", BUNDLE);

      // One secret per domain, so exactly one HTTP call.
      expect(fetchMock).toHaveBeenCalledOnce();
      const [url, init] = callOf(fetchMock, 0);
      expect(url).toContain("/api/v4/secrets/example.com");
      expect(init.method).toBe("POST");

      const body = bodyOf([url, init]);
      expect(body.secretPath).toBe("/certs");
      expect(body.projectId).toBe("proj");
      expect(body.environment).toBe("prod");
      expect(body.type).toBe("shared");
    });

    it("round-trips the bundle through JSON with raw PEM intact", async () => {
      const fetchMock = vi.fn(async () => jsonResponse({}));
      const client = makeClient(fetchMock);

      await writeCertBundle(client, target, "certs/example.com", BUNDLE);

      const body = bodyOf(callOf(fetchMock, 0));
      const parsed = JSON.parse(body.secretValue!) as CertBundle;
      expect(parsed).toEqual(BUNDLE);
      // Raw PEM, not base64-encoded material.
      expect(parsed.fullchain).toBe(BUNDLE.fullchain);
      expect(parsed.privateKey).toBe(KEY_PEM);
      expect(parsed.chain).toBe(INTER_PEM);
      expect(parsed.fullchain).toContain("-----BEGIN CERTIFICATE-----");
      expect(parsed.privateKey).toContain("-----BEGIN PRIVATE KEY-----");
    });

    it("splits 'certs/<domain>' into path '/certs' and name '<domain>'", async () => {
      const fetchMock = vi.fn(async () => jsonResponse({}));
      const client = makeClient(fetchMock);

      await writeCertBundle(client, target, "certs/aribudi.com", BUNDLE);

      const [url, init] = callOf(fetchMock, 0);
      expect(url).toContain("/api/v4/secrets/aribudi.com");
      // The name segment must not carry the path.
      expect(url).not.toContain("certs/aribudi.com");
      expect(bodyOf([url, init]).secretPath).toBe("/certs");
    });

    it("fails when the upsert cannot be written", async () => {
      const fetchMock = vi.fn(async () => jsonResponse({ error: "nope" }, 500));
      const client = makeClient(fetchMock);
      await expect(
        writeCertBundle(client, target, "certs/example.com", BUNDLE),
      ).rejects.toThrow();
    });
  });

  describe("readCertBundle", () => {
    it("returns the parsed bundle when the secret exists", async () => {
      const fetchMock = vi.fn(async () =>
        jsonResponse({ secret: { secretValue: JSON.stringify(BUNDLE) } }),
      );
      const client = makeClient(fetchMock);

      const bundle = await readCertBundle(client, target, "certs/example.com");

      expect(bundle).toEqual(BUNDLE);
      expect(fetchMock).toHaveBeenCalledOnce();
      const [url] = callOf(fetchMock, 0);
      expect(url).toContain("/api/v4/secrets/example.com");
      expect(url).toContain("secretPath=%2Fcerts");
    });

    it("returns undefined when the secret is missing", async () => {
      const fetchMock = vi.fn(async () => jsonResponse({ error: "not found" }, 404));
      const client = makeClient(fetchMock);
      expect(await readCertBundle(client, target, "certs/example.com")).toBeUndefined();
    });

    it("returns undefined when the value is not JSON", async () => {
      const fetchMock = vi.fn(async () =>
        jsonResponse({ secret: { secretValue: "not json at all" } }),
      );
      const client = makeClient(fetchMock);
      expect(await readCertBundle(client, target, "certs/example.com")).toBeUndefined();
    });

    it("returns undefined when the secret value is empty", async () => {
      const fetchMock = vi.fn(async () => jsonResponse({ secret: { secretValue: "" } }));
      const client = makeClient(fetchMock);
      expect(await readCertBundle(client, target, "certs/example.com")).toBeUndefined();
    });
  });
});
