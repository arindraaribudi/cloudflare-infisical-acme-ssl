export interface CloudflareDnsOptions {
  apiToken: string;
  fetch?: typeof fetch;
  pollIntervalMs?: number;
  timeoutMs?: number;
}

export interface CreateTxtInput {
  zoneId: string;
  name: string;
  content: string;
  ttl?: number;
}

export interface DeleteTxtInput {
  zoneId: string;
  recordId: string;
}

export interface PollInput {
  zoneId: string;
  name: string;
  content: string;
}

const DEFAULT_BASE = "https://api.cloudflare.com/client/v4";

// Cloudflare returns TXT content wrapped in double quotes ("TXT content without
// any quotes, Cloudflare will automatically add double quotes").
const unquote = (value: string): string =>
  value.length >= 2 && value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;

export class CloudflareDns {
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;
  private readonly pollIntervalMs: number;
  private readonly timeoutMs: number;

  constructor(opts: CloudflareDnsOptions) {
    this.token = opts.apiToken;
    this.fetchImpl = (opts.fetch ?? fetch).bind(globalThis);
    this.pollIntervalMs = opts.pollIntervalMs ?? 2000;
    this.timeoutMs = opts.timeoutMs ?? 60000;
  }

  private headers(): HeadersInit {
    return {
      Authorization: `Bearer ${this.token}`,
      "Content-Type": "application/json",
    };
  }

  private async okOrThrow(res: Response, ctx: string): Promise<unknown> {
    if (res.ok) {
      const body = (await res.json()) as { result?: unknown; errors?: { message: string }[] };
      if (body.errors && body.errors.length > 0) {
        throw new Error(`CF DNS ${ctx}: ${body.errors.map((e) => e.message).join(", ")}`);
      }
      return body.result;
    }
    const text = await res.text().catch(() => "");
    throw new Error(`CF DNS ${ctx}: HTTP ${res.status} ${text}`);
  }

  async createTxt(input: CreateTxtInput): Promise<string> {
    const url = `${DEFAULT_BASE}/zones/${input.zoneId}/dns_records`;
    const body = {
      type: "TXT",
      name: input.name,
      content: input.content,
      ttl: input.ttl ?? 60,
    };
    const res = await this.fetchImpl(url, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    const result = (await this.okOrThrow(res, "createTxt")) as { id: string };
    return result.id;
  }

  async deleteTxt(input: DeleteTxtInput): Promise<void> {
    const url = `${DEFAULT_BASE}/zones/${input.zoneId}/dns_records/${input.recordId}`;
    const res = await this.fetchImpl(url, {
      method: "DELETE",
      headers: this.headers(),
    });
    await this.okOrThrow(res, "deleteTxt");
  }

  async pollTxtPropagated(input: PollInput): Promise<boolean> {
    const url = `${DEFAULT_BASE}/zones/${input.zoneId}/dns_records?type=TXT&name=${encodeURIComponent(input.name)}`;
    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      const res = await this.fetchImpl(url, { method: "GET", headers: this.headers() });
      const result = (await this.okOrThrow(res, "poll")) as { content: string }[];
      if (Array.isArray(result) && result.some((r) => unquote(r.content) === input.content)) {
        return true;
      }
      await new Promise((r) => setTimeout(r, this.pollIntervalMs));
    }
    return false;
  }
}
