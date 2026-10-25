import { describe, it, expect, vi } from "vitest";
import { CloudflareDns } from "../../src/lib/dns-cloudflare";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("CloudflareDns", () => {
  const token = "cf-token";

  it("createTxt POSTs to the zone and returns the record id", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ result: { id: "rec-1", content: "v=txt-value" } }),
    );
    const dns = new CloudflareDns({ apiToken: token, fetch: fetchMock as unknown as typeof fetch });
    const id = await dns.createTxt({
      zoneId: "z-1",
      name: "_acme-challenge.example.com",
      content: "v=txt-value",
    });
    expect(id).toBe("rec-1");
    const [url, init] = fetchMock.mock.calls[0]! as unknown as [string, RequestInit];
    expect(url).toBe("https://api.cloudflare.com/client/v4/zones/z-1/dns_records");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toMatchObject({
      type: "TXT", name: "_acme-challenge.example.com", content: "v=txt-value",
    });
  });

  it("deleteTxt DELETEs by record id", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ result: { id: "rec-1" } }));
    const dns = new CloudflareDns({ apiToken: token, fetch: fetchMock as unknown as typeof fetch });
    await dns.deleteTxt({ zoneId: "z-1", recordId: "rec-1" });
    const [url, init] = fetchMock.mock.calls[0]! as unknown as [string, RequestInit];
    expect(url).toBe("https://api.cloudflare.com/client/v4/zones/z-1/dns_records/rec-1");
    expect(init.method).toBe("DELETE");
  });

  it("pollTxtPropagated returns true when readback shows the content", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ result: [] }))
      .mockResolvedValueOnce(
        jsonResponse({ result: [{ content: "v=txt-value" }] }),
      );
    const dns = new CloudflareDns({
      apiToken: token, fetch: fetchMock as unknown as typeof fetch,
      pollIntervalMs: 1, timeoutMs: 100,
    });
    const ok = await dns.pollTxtPropagated({
      zoneId: "z-1", name: "_acme-challenge.example.com", content: "v=txt-value",
    });
    expect(ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("pollTxtPropagated matches content returned wrapped in double quotes", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ result: [{ content: '"v=txt-value"' }] }),
    );
    const dns = new CloudflareDns({
      apiToken: token, fetch: fetchMock as unknown as typeof fetch,
      pollIntervalMs: 1, timeoutMs: 100,
    });
    const ok = await dns.pollTxtPropagated({
      zoneId: "z-1", name: "_acme-challenge.example.com", content: "v=txt-value",
    });
    expect(ok).toBe(true);
  });

  it("pollTxtPropagated returns false when the quoted content differs", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ result: [{ content: '"other-value"' }] }),
    );
    const dns = new CloudflareDns({
      apiToken: token, fetch: fetchMock as unknown as typeof fetch,
      pollIntervalMs: 1, timeoutMs: 5,
    });
    const ok = await dns.pollTxtPropagated({
      zoneId: "z-1", name: "_acme-challenge.example.com", content: "v=txt-value",
    });
    expect(ok).toBe(false);
  });

  it("pollTxtPropagated returns false on timeout", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ result: [] }));
    const dns = new CloudflareDns({
      apiToken: token, fetch: fetchMock as unknown as typeof fetch,
      pollIntervalMs: 1, timeoutMs: 5,
    });
    const ok = await dns.pollTxtPropagated({
      zoneId: "z-1", name: "_acme-challenge.example.com", content: "v=never",
    });
    expect(ok).toBe(false);
  });

  it("throws on API error for createTxt", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ errors: [{ message: "x" }] }, 400));
    const dns = new CloudflareDns({ apiToken: token, fetch: fetchMock as unknown as typeof fetch });
    await expect(
      dns.createTxt({ zoneId: "z", name: "n", content: "v" }),
    ).rejects.toThrow(/CF DNS/);
  });
});
