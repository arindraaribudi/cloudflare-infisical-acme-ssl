export interface InfisicalOptions {
  baseUrl: string;
  fetch?: typeof fetch;
}

export interface SecretRequest {
  token: string;
  projectId: string;
  env: string;
  key: string;
}

export interface UpsertRequest extends SecretRequest {
  value: string;
}

/**
 * Split a flat config key into the v4 path/name pair.
 * "certs/example.com" -> { secretPath: "/certs", secretName: "example.com" }
 * "ACME_ACCOUNT"      -> { secretPath: "/", secretName: "ACME_ACCOUNT" }
 */
function splitKey(key: string): { secretPath: string; secretName: string } {
  const idx = key.lastIndexOf("/");
  const rawPath = idx === -1 ? "" : key.slice(0, idx);
  const secretName = idx === -1 ? key : key.slice(idx + 1);
  if (!secretName) {
    throw new Error(`Infisical invalid secret key: "${key}"`);
  }
  const segments = rawPath.split("/").filter(Boolean);
  return {
    secretPath: segments.length ? `/${segments.join("/")}` : "/",
    secretName,
  };
}

export class InfisicalClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: InfisicalOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.fetchImpl = (opts.fetch ?? fetch).bind(globalThis);
  }

  private authHeaders(token: string): HeadersInit {
    return {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    };
  }

  async getSecret(req: SecretRequest): Promise<string> {
    const { secretPath, secretName } = splitKey(req.key);
    const qs = new URLSearchParams({
      projectId: req.projectId,
      environment: req.env,
      secretPath,
      type: "shared",
    });
    const url = `${this.baseUrl}/api/v4/secrets/${encodeURIComponent(secretName)}?${qs.toString()}`;
    const res = await this.fetchImpl(url, {
      method: "GET",
      headers: this.authHeaders(req.token),
    });
    if (!res.ok) {
      throw new Error(`Infisical getSecret(${secretName}) failed: ${res.status}`);
    }
    const body = (await res.json()) as { secret?: { secretValue?: string } };
    if (!body.secret?.secretValue) {
      throw new Error(`Infisical getSecret(${secretName}) returned empty`);
    }
    return body.secret.secretValue;
  }

  async upsertSecret(req: UpsertRequest): Promise<void> {
    const { secretPath, secretName } = splitKey(req.key);
    const url = `${this.baseUrl}/api/v4/secrets/${encodeURIComponent(secretName)}`;
    const body = JSON.stringify({
      projectId: req.projectId,
      environment: req.env,
      secretPath,
      secretValue: req.value,
      type: "shared",
    });
    const create = await this.fetchImpl(url, {
      method: "POST",
      headers: this.authHeaders(req.token),
      body,
    });
    if (create.ok) return;
    const patch = await this.fetchImpl(url, {
      method: "PATCH",
      headers: this.authHeaders(req.token),
      body,
    });
    if (patch.ok) return;
    throw new Error(
      `Infisical upsert(${secretName}) failed: POST ${create.status}, PATCH ${patch.status}`,
    );
  }
}
