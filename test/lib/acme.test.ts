import { describe, it, expect, vi, beforeEach } from "vitest";
import * as acme from "acme-client";
import {
  isFresh,
  buildBundle,
  ensureAccount,
  issueWildcard,
  parseNotAfter,
} from "../../src/lib/acme";

vi.mock("acme-client", () => {
  const Client = vi.fn();
  return {
    Client,
    // src/lib/acme.ts assigns the axios adapter at import time.
    axios: { defaults: {} },
    directory: {
      letsencrypt: {
        production: "https://acme-v02.api.letsencrypt.org/directory",
        staging: "https://acme-staging-v02.api.letsencrypt.org/directory",
      },
    },
    crypto: {
      createPrivateKey: vi.fn(),
      createCsr: vi.fn(),
      readCertificateInfo: vi.fn(),
    },
  };
});

// Real self-signed certificate (generated with:
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out fixture.pem \
//     -days 36500 -subj "/CN=example.com"
//) used here as a realistic PEM input. The certificate reader
// (`acme.crypto.readCertificateInfo`) is mocked in this file, so the expiry
// asserted by `parseNotAfter` (2026-03-01T00:00:00.000Z) comes from that mock —
// not from this fixture, which the real reader never parses in this file.
// The real parse is covered by a runtime probe against a real workerd runtime.
const SELF_SIGNED_PEM = `-----BEGIN CERTIFICATE-----
MIIC7jCCAdagAwIBAgIUDENVMSIDBVhf6JBxdFF6S03Dt1MwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wIBcNMjYxMDI0MTgzMzI0WhgPMjEy
NjA5MzAxODMzMjRaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwdrDdCscDoHb71y07H803iFrpFuG0YsORR6H
28rrghVxXIE/GVp5lOrrqlYzWSMF3ou4Ds5MMz0lO24AIYUrTk1ledOolZiT+nAI
QXq3rp3Kr+43yUvFkk9pt9nYaMvxn0T3BsXRqd7ZRH6+LjwvAFlFXqWdNRkM5SBG
IYWAU5nDRD9nZ0WJANPHByXgcVWKwRLegFMumu23efUJUMqo5RpPQO/l2utL7anN
3+6tALHauQ/aCJ09GeSU5RNI0QSxxuySQ7KOlORuSRgc1yPMflz+rLqj1rLkJocv
n8qrVWWnBQJiAvxWW5vbM1NPL0c431E520OeUSTAXRpojSUVzwIDAQABozIwMDAd
BgNVHQ4EFgQUeT2wL/VWgVl0oWoF1/sahwnOHZowDwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQsFAAOCAQEAwVFxaUxi/ubu4DA0ZMMfpwhjCWvgGvynAF618fiC
QvciQ+FOT4lumQbwTE1lQQdcnCFkYM13Ur/Gc5AA/hqUx2Jo6uMj8z1Edht2iVWI
NoyOj6h/sj4+YLWiYbAxMAo/UEn8WCZlvgGNk3cw1C0eenV6Z0RZ528qWaNYj2Ti
dz1Z78ECf/bgX8fgwGmKbNzxjIKim5YN7iO3jZnEGIula34qNnafRssLUOQiReq9
MX0sbDTTfFUngtPhezRB4TzDF5uiF+C0ngnufKpcXM2U7bSch7Pvrt+64DcMIbbv
TwyM58nMTHG3oDL17EiaO8WoKmjrfSqE+t/uGRjtamIdZQ==
-----END CERTIFICATE-----`;

beforeEach(() => {
  vi.mocked(acme.Client).mockReset();
  vi.mocked(acme.crypto.createPrivateKey).mockReset();
  vi.mocked(acme.crypto.createCsr).mockReset();
  vi.mocked(acme.crypto.readCertificateInfo).mockReset();
  // Emulate the real reader: it throws on anything that is not a certificate PEM.
  vi.mocked(acme.crypto.readCertificateInfo).mockImplementation((certPem) => {
    if (!String(certPem).includes("-----BEGIN CERTIFICATE-----")) {
      throw new Error("Failed to parse certificate");
    }
    return {
      issuer: { commonName: "example.com" },
      domains: { commonName: "example.com", altNames: [] },
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2026-03-01T00:00:00Z"),
    };
  });
});

describe("acme helpers", () => {
  it("isFresh: cert valid beyond threshold is fresh", () => {
    const future = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString();
    expect(isFresh({ notAfter: future } as any, 30)).toBe(true);
  });

  it("isFresh: cert within threshold is stale", () => {
    const soon = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString();
    expect(isFresh({ notAfter: soon } as any, 30)).toBe(false);
  });

  it("isFresh: cert already expired is stale", () => {
    const past = new Date(Date.now() - 1000).toISOString();
    expect(isFresh({ notAfter: past } as any, 30)).toBe(false);
  });

  it("isFresh: undefined cert is stale", () => {
    expect(isFresh(undefined, 30)).toBe(false);
  });

  it("buildBundle keeps PEMs unencoded and pins environment", () => {
    const bundle = buildBundle({
      apex: "example.com",
      fullchainPem: "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----",
      privateKeyPem: "-----BEGIN PRIVATE KEY-----\nDEF\n-----END PRIVATE KEY-----",
      chainPem: "-----BEGIN CERTIFICATE-----\nGHI\n-----END CERTIFICATE-----",
      notAfter: "2026-12-14T00:00:00Z",
      acmeEnv: "production",
    });
    expect(bundle.apex).toBe("example.com");
    expect(bundle.fullchain).toBe("-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----");
    expect(bundle.privateKey).toBe("-----BEGIN PRIVATE KEY-----\nDEF\n-----END PRIVATE KEY-----");
    expect(bundle.chain).toBe("-----BEGIN CERTIFICATE-----\nGHI\n-----END CERTIFICATE-----");
    expect(bundle.acmeEnv).toBe("production");
  });
});

describe("parseNotAfter", () => {
  it("returns the certificate's expiry as an ISO string", () => {
    expect(parseNotAfter(SELF_SIGNED_PEM)).toBe("2026-03-01T00:00:00.000Z");
    expect(acme.crypto.readCertificateInfo).toHaveBeenCalledWith(SELF_SIGNED_PEM);
  });

  it("returns undefined for a non-PEM string", () => {
    expect(parseNotAfter("not a pem")).toBeUndefined();
  });

  it("passes the whole chain to the reader, which decodes only the leaf", () => {
    const chain = `${SELF_SIGNED_PEM}\n-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----`;
    expect(parseNotAfter(chain)).toBe("2026-03-01T00:00:00.000Z");
    expect(acme.crypto.readCertificateInfo).toHaveBeenCalledWith(chain);
  });
});

describe("ensureAccount", () => {
  it("creates + persists account when none exists", async () => {
    const upsert = vi.fn(async () => {});
    const createAccount = vi.fn(async () => ({ status: "valid" }));
    const getAccountUrl = vi.fn(() => "https://acme.example/acct/1");
    vi.mocked(acme.crypto.createPrivateKey).mockResolvedValue(Buffer.from("PEM-KEY"));
    vi.mocked(acme.Client).mockImplementation(() => ({ createAccount, getAccountUrl }) as any);

    const acc = await ensureAccount({
      existingJson: undefined,
      upsert,
      acmeEnv: "production",
      email: "ops@example.com",
    });
    expect(acc.accountUrl).toBe("https://acme.example/acct/1");
    expect(acc.emails).toEqual(["ops@example.com"]);
    expect(createAccount).toHaveBeenCalledWith({
      termsOfServiceAgreed: true,
      contact: ["mailto:ops@example.com"],
    });
    expect(upsert).toHaveBeenCalledOnce();
  });

  it("creates an account with no contact field when no email is given", async () => {
    const upsert = vi.fn(async () => {});
    const createAccount = vi.fn(async () => ({ status: "valid" }));
    const getAccountUrl = vi.fn(() => "https://acme.example/acct/2");
    vi.mocked(acme.crypto.createPrivateKey).mockResolvedValue(Buffer.from("PEM-KEY"));
    vi.mocked(acme.Client).mockImplementation(() => ({ createAccount, getAccountUrl }) as any);

    const acc = await ensureAccount({
      existingJson: undefined,
      upsert,
      acmeEnv: "production",
    });
    expect(acc.accountUrl).toBe("https://acme.example/acct/2");
    expect(acc.emails).toEqual([]);
    // Deep equality: an extra `contact` key would fail this assertion.
    expect(createAccount).toHaveBeenCalledWith({ termsOfServiceAgreed: true });
    expect(upsert).toHaveBeenCalledOnce();
  });

  it("throws when the account URL cannot be determined", async () => {
    const upsert = vi.fn(async () => {});
    vi.mocked(acme.crypto.createPrivateKey).mockResolvedValue(Buffer.from("PEM-KEY"));
    vi.mocked(acme.Client).mockImplementation(
      () =>
        ({
          createAccount: vi.fn(async () => ({ status: "valid" })),
          getAccountUrl: vi.fn(() => {
            throw new Error("No account URL found, register account first");
          }),
        }) as any,
    );

    await expect(
      ensureAccount({ existingJson: undefined, upsert, acmeEnv: "production" }),
    ).rejects.toThrow(/account URL/i);
    expect(upsert).not.toHaveBeenCalled();
  });

  it("reuses existing account when present", async () => {
    const upsert = vi.fn(async () => {});
    const existingJson = JSON.stringify({
      keyPem: "PEM",
      accountUrl: "https://example.com/acct/9",
      emails: ["ops@example.com"],
      acmeEnv: "production",
    });
    const acc = await ensureAccount({ existingJson, upsert, acmeEnv: "production" });
    expect(acc.accountUrl).toBe("https://example.com/acct/9");
    expect(upsert).not.toHaveBeenCalled();
    expect(acme.Client).not.toHaveBeenCalled();
  });

  it("throws when existing account has different acmeEnv", async () => {
    const upsert = vi.fn(async () => {});
    const existingJson = JSON.stringify({
      keyPem: "PEM",
      accountUrl: "url",
      emails: ["x"],
      acmeEnv: "staging",
    });
    await expect(
      ensureAccount({ existingJson, upsert, acmeEnv: "production" }),
    ).rejects.toThrow(/acmeEnv/);
  });
});

describe("issueWildcard", () => {
  const LEAF_PEM = "-----BEGIN CERTIFICATE-----\nLEAFBODY\n-----END CERTIFICATE-----";
  const INTERMEDIATE_PEM =
    "-----BEGIN CERTIFICATE-----\nINTBODY\n-----END CERTIFICATE-----";

  function mockClient(certPem: string) {
    return {
      createOrder: vi.fn(async () => ({
        url: "https://example/order/1",
        identifiers: [
          { type: "dns", value: "*.example.com" },
          { type: "dns", value: "example.com" },
        ],
        authorizations: ["https://example/authz/1", "https://example/authz/2"],
        finalize: "https://example/finalize/1",
        status: "pending",
      })),
      getAuthorizations: vi.fn(async () => [
        {
          identifier: { type: "dns", value: "example.com" },
          wildcard: true,
          challenges: [
            {
              type: "dns-01",
              url: "https://example/chal/1",
              token: "tok-1",
              status: "pending",
            },
          ],
        },
        {
          identifier: { type: "dns", value: "example.com" },
          wildcard: false,
          challenges: [
            {
              type: "dns-01",
              url: "https://example/chal/2",
              token: "tok-2",
              status: "pending",
            },
          ],
        },
      ]),
      getChallengeKeyAuthorization: vi.fn(
        async (challenge: { token: string }) => `key-auth-${challenge.token}`,
      ),
      verifyChallenge: vi.fn(async () => true),
      completeChallenge: vi.fn(async (challenge: unknown) => challenge),
      waitForValidStatus: vi.fn(async (item: unknown) => item),
      finalizeOrder: vi.fn(async () => ({
        url: "https://example/order/1",
        identifiers: [
          { type: "dns", value: "*.example.com" },
          { type: "dns", value: "example.com" },
        ],
        authorizations: ["https://example/authz/1", "https://example/authz/2"],
        finalize: "https://example/finalize/1",
        certificate: "https://example/cert/1.pem",
        status: "valid",
      })),
      getCertificate: vi.fn(async () => certPem),
    };
  }

  it("runs the full DNS-01 flow for apex + wildcard", async () => {
    let recordN = 0;
    const dns = {
      createTxt: vi.fn(async () => `rec-${++recordN}`),
      deleteTxt: vi.fn(async () => undefined),
      pollTxtPropagated: vi.fn(async () => true),
    };

    vi.mocked(acme.crypto.createPrivateKey).mockResolvedValue(Buffer.from("PRIV-PEM"));
    vi.mocked(acme.crypto.createCsr).mockResolvedValue([
      Buffer.from("PRIV-PEM"),
      Buffer.from("CSR"),
    ]);
    const client = mockClient(`${LEAF_PEM}\n${INTERMEDIATE_PEM}`);
    vi.mocked(acme.Client).mockImplementation(() => client as any);

    const bundle = await issueWildcard({
      apex: "example.com",
      zoneId: "z-1",
      accountJson: JSON.stringify({
        keyPem: "ACCT-PEM",
        accountUrl: "https://example.com/acct/1",
        emails: ["o@x"],
        acmeEnv: "production",
      }),
      dns,
    });

    expect(bundle.apex).toBe("example.com");
    expect(bundle.privateKey).toBe("PRIV-PEM");
    // notAfter comes from the issued certificate, not a hardcoded offset.
    expect(bundle.notAfter).toBe("2026-03-01T00:00:00.000Z");

    // Order identifiers are wildcard-first, matching the CSR DNS-name order.
    expect(client.createOrder).toHaveBeenCalledWith({
      identifiers: [
        { type: "dns", value: "*.example.com" },
        { type: "dns", value: "example.com" },
      ],
    });

    // One TXT record per authorization, same name, different contents.
    expect(dns.createTxt).toHaveBeenCalledTimes(2);
    expect(dns.createTxt).toHaveBeenCalledWith({
      zoneId: "z-1",
      name: "_acme-challenge.example.com",
      content: "key-auth-tok-1",
    });
    expect(dns.createTxt).toHaveBeenCalledWith({
      zoneId: "z-1",
      name: "_acme-challenge.example.com",
      content: "key-auth-tok-2",
    });

    // Propagation is polled once per expected content.
    expect(dns.pollTxtPropagated).toHaveBeenCalledTimes(2);
    expect(dns.pollTxtPropagated).toHaveBeenCalledWith({
      zoneId: "z-1",
      name: "_acme-challenge.example.com",
      content: "key-auth-tok-1",
    });
    expect(dns.pollTxtPropagated).toHaveBeenCalledWith({
      zoneId: "z-1",
      name: "_acme-challenge.example.com",
      content: "key-auth-tok-2",
    });

    // No local DNS pre-check: acme-client's verifyChallenge resolves TXT via
    // node:dns, which is unreliable in workerd. The CA validates DNS-01 itself.
    expect(client.verifyChallenge).not.toHaveBeenCalled();
    expect(client.completeChallenge).toHaveBeenCalledTimes(2);
    // Twice for the challenges, once for the finalized order.
    expect(client.waitForValidStatus).toHaveBeenCalledTimes(3);

    // Every TXT propagation poll must precede the first challenge completion.
    const pollOrders = dns.pollTxtPropagated.mock.invocationCallOrder;
    const completeOrders = client.completeChallenge.mock.invocationCallOrder;
    expect(Math.max(...pollOrders)).toBeLessThan(Math.min(...completeOrders));

    // Both TXT records are cleaned up.
    expect(dns.deleteTxt).toHaveBeenCalledTimes(2);
    expect(dns.deleteTxt).toHaveBeenCalledWith({ zoneId: "z-1", recordId: "rec-1" });
    expect(dns.deleteTxt).toHaveBeenCalledWith({ zoneId: "z-1", recordId: "rec-2" });

    expect(acme.crypto.createCsr).toHaveBeenCalledWith(
      { commonName: "*.example.com", altNames: ["example.com"] },
      expect.anything(),
    );

    // fullchain = leaf + intermediates; chain = intermediates only.
    const fullchain = bundle.fullchain;
    const chain = bundle.chain;
    expect(fullchain).toContain("LEAFBODY");
    expect(fullchain).toContain("INTBODY");
    expect(fullchain.indexOf("LEAFBODY")).toBeLessThan(fullchain.indexOf("INTBODY"));
    expect(chain).toContain("INTBODY");
    expect(chain).not.toContain("LEAFBODY");
  });

  it("falls back to a conservative ~60 day notAfter when the certificate cannot be parsed", async () => {
    const dns = {
      createTxt: vi.fn(async () => "rec-1"),
      deleteTxt: vi.fn(async () => undefined),
      pollTxtPropagated: vi.fn(async () => true),
    };

    vi.mocked(acme.crypto.createPrivateKey).mockResolvedValue(Buffer.from("PRIV-PEM"));
    vi.mocked(acme.crypto.createCsr).mockResolvedValue([
      Buffer.from("PRIV-PEM"),
      Buffer.from("CSR"),
    ]);
    // Invalid PEM: the certificate reader throws.
    vi.mocked(acme.crypto.readCertificateInfo).mockImplementation(() => {
      throw new Error("Failed to parse certificate");
    });
    vi.mocked(acme.Client).mockImplementation(() => mockClient("CERT") as any);

    const before = Date.now();
    const bundle = await issueWildcard({
      apex: "example.com",
      zoneId: "z-1",
      accountJson: JSON.stringify({
        keyPem: "ACCT-PEM",
        accountUrl: "https://example.com/acct/1",
        emails: ["o@x"],
        acmeEnv: "production",
      }),
      dns,
    });

    const day = 24 * 60 * 60 * 1000;
    const notAfterMs = Date.parse(bundle.notAfter);
    expect(notAfterMs).toBeGreaterThan(before + 59 * day);
    expect(notAfterMs).toBeLessThan(before + 61 * day);
    // Explicitly NOT the old hardcoded +90 days.
    expect(notAfterMs).toBeLessThan(before + 89 * day);
  });
});
