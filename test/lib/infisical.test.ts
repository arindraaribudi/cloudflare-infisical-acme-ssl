import { describe, it, expect, vi } from "vitest";
import { InfisicalClient } from "../../src/lib/infisical";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("InfisicalClient", () => {
  const baseUrl = "https://app.infisical.com";
  const token = "svc.token";

  function makeClient(fetchMock: unknown): InfisicalClient {
    return new InfisicalClient({ baseUrl, fetch: fetchMock as unknown as typeof fetch });
  }

  function callOf(fetchMock: { mock: { calls: unknown[][] } }, index: number): [string, RequestInit] {
    return fetchMock.mock.calls[index]! as unknown as [string, RequestInit];
  }

  it("getSecret uses the v4 route for a key without a slash", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ secret: { secretValue: "raw-pem" } }),
    );
    const client = makeClient(fetchMock);
    const value = await client.getSecret({
      token,
      projectId: "proj",
      env: "prod",
      key: "FOO",
    });
    expect(value).toBe("raw-pem");
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = callOf(fetchMock, 0);
    expect(url).toContain("/api/v4/secrets/FOO");
    expect(url).toContain("projectId=proj");
    expect(url).toContain("environment=prod");
    expect(url).toContain("secretPath=%2F");
    expect(url).toContain("type=shared");
    expect(url).not.toContain("/api/v3/");
    expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${token}`);
  });

  it("getSecret splits a slashed key into secretPath and secretName", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ secret: { secretValue: "raw-pem" } }),
    );
    const client = makeClient(fetchMock);
    await client.getSecret({
      token,
      projectId: "proj",
      env: "prod",
      key: "certs/example.com",
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url] = callOf(fetchMock, 0);
    expect(url).toContain("/api/v4/secrets/example.com");
    expect(url).toContain("secretPath=%2Fcerts");
    // The name segment must not carry the path.
    expect(url).not.toContain("certs/example.com");
    expect(url).not.toContain("certs%2Fexample.com");
  });

  it("getSecret returns parsed JSON for a JSON-shaped secret", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ secret: { secretValue: '{"a":1}' } }),
    );
    const client = makeClient(fetchMock);
    const value = await client.getSecret({
      token,
      projectId: "proj",
      env: "prod",
      key: "FOO",
    });
    expect(JSON.parse(value)).toEqual({ a: 1 });
  });

  it("getSecret returns raw string for non-JSON value", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ secret: { secretValue: "raw-pem" } }),
    );
    const client = makeClient(fetchMock);
    const value = await client.getSecret({
      token, projectId: "proj", env: "prod", key: "FOO",
    });
    expect(value).toBe("raw-pem");
  });

  it("getSecret throws on non-OK response", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ error: "no" }, 404));
    const client = makeClient(fetchMock);
    await expect(
      client.getSecret({ token, projectId: "proj", env: "prod", key: "MISSING" }),
    ).rejects.toThrow();
  });

  it("getSecret rejects an invalid key", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ secret: { secretValue: "x" } }));
    const client = makeClient(fetchMock);
    await expect(
      client.getSecret({ token, projectId: "proj", env: "prod", key: "certs/" }),
    ).rejects.toThrow(/certs\//);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("upsertSecret POSTs the v4 body and stops on 200", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({}, 200));
    const client = makeClient(fetchMock);
    await client.upsertSecret({
      token, projectId: "proj", env: "prod", key: "FOO", value: "bar",
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = callOf(fetchMock, 0);
    expect(init.method).toBe("POST");
    expect(url).toContain("/api/v4/secrets/FOO");
    expect(url).not.toContain("?");
    expect(JSON.parse(init.body as string)).toEqual({
      projectId: "proj",
      environment: "prod",
      secretPath: "/",
      secretValue: "bar",
      type: "shared",
    });
  });

  it("upsertSecret falls back to PATCH when POST fails", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ error: "secret already exists" }, 409))
      .mockResolvedValueOnce(jsonResponse({}));
    const client = makeClient(fetchMock);
    await client.upsertSecret({
      token, projectId: "proj", env: "prod", key: "FOO", value: "bar",
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [postUrl, postInit] = callOf(fetchMock, 0);
    const [patchUrl, patchInit] = callOf(fetchMock, 1);
    expect(postInit.method).toBe("POST");
    expect(patchInit.method).toBe("PATCH");
    expect(patchUrl).toBe(postUrl);
    expect(patchUrl).toContain("/api/v4/secrets/FOO");
    expect(JSON.parse(patchInit.body as string)).toEqual({
      projectId: "proj",
      environment: "prod",
      secretPath: "/",
      secretValue: "bar",
      type: "shared",
    });
  });

  it("upsertSecret throws when POST and PATCH both fail", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ error: "secret already exists" }, 409))
      .mockResolvedValueOnce(jsonResponse({ error: "bad request" }, 400));
    const client = makeClient(fetchMock);
    const err = await client
      .upsertSecret({
        token, projectId: "proj", env: "prod", key: "FOO", value: "super-secret-value",
      })
      .then(() => undefined)
      .catch((e: unknown) => e as Error);
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toContain("FOO");
    expect(err!.message).toContain("409");
    expect(err!.message).toContain("400");
    expect(err!.message).not.toContain("super-secret-value");
  });
});
