import { InfisicalClient } from "./lib/infisical";
import { CloudflareDns } from "./lib/dns-cloudflare";
import { ensureAccount, issueWildcard, isFresh, CertBundle } from "./lib/acme";
import { loadConfig, ValidatedConfig } from "./lib/config";
import { readCertBundle, writeCertBundle } from "./lib/cert-store";

export interface Env {
  INFISICAL_SERVICE_TOKEN: string;
  INFISICAL_PROJECT_ID: string;
  /** Infisical "environment" name the Worker reads/writes in (staging | prod | dev). Default "prod". */
  INFISICAL_NAMESPACE?: string;
  DEBUG_RENEW_TOKEN?: string;
}

const INFISICAL_BASE = "https://app.infisical.com";

export default {
  async scheduled(_controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    const token = env.INFISICAL_SERVICE_TOKEN;
    const projectId = env.INFISICAL_PROJECT_ID;
    const ns = env.INFISICAL_NAMESPACE ?? "prod";
    const infisical = new InfisicalClient({ baseUrl: INFISICAL_BASE });
    const debugFetch = fetch;

    // 1. Load config + secrets
    const cfgRaw = await infisical.getSecret({ token, projectId, env: ns, key: "CF_WORKER_CONFIG" });
    const cfg: ValidatedConfig = await loadConfig(cfgRaw);
    const cfToken = await infisical.getSecret({ token, projectId, env: ns, key: "CF_API_TOKEN" });
    const accountJson = await infisical.getSecret({
      token, projectId, env: ns, key: cfg.paths.account,
    }).catch(() => undefined);

    const dns = new CloudflareDns({ apiToken: cfToken, fetch: debugFetch });

    // 2. Per-apex parallel work
    const results = await Promise.allSettled(
      cfg.apexes.map((apex) => runApex({ apex, cfg, infisical, dns, accountJson, token, projectId, ns })),
    );

    // 3. Write run summary
    const perApex = results.map((r, i) => {
      const apex = cfg.apexes[i]!;
      if (r.status === "fulfilled") return r.value;
      return { apex, action: "failed", success: false, error: String(r.reason) };
    });

    const summary = {
      finishedAt: new Date().toISOString(),
      success: perApex.every((p) => p.success),
      acmeEnv: cfg.acmeEnv,
      perApex,
    };

    await infisical.upsertSecret({
      token, projectId, env: ns, key: cfg.paths.status, value: JSON.stringify(summary),
    });

    if (!summary.success) {
      throw new Error("One or more apex renewals failed; see STATUS_LAST_RUN");
    }
  },

  async fetch(req: Request, env: Env): Promise<Response> {
    if (new URL(req.url).pathname !== "/renew") {
      return new Response("Not found", { status: 404 });
    }
    if (req.headers.get("X-Debug-Secret") !== env.DEBUG_RENEW_TOKEN || !env.DEBUG_RENEW_TOKEN) {
      return new Response("Forbidden", { status: 403 });
    }
    return new Response("use cron", { status: 501 });
  },
};

async function runApex(args: {
  apex: string;
  cfg: ValidatedConfig;
  infisical: InfisicalClient;
  dns: CloudflareDns;
  accountJson: string | undefined;
  token: string;
  projectId: string;
  ns: string;
}): Promise<{ apex: string; action: "renewed" | "skipped" | "failed"; success: boolean; notAfter?: string; error?: string }> {
  const { apex, cfg, infisical, dns, accountJson, token, projectId, ns } = args;

  try {
    const certKey = cfg.paths.cert.replace("<domain>", apex);
    const existing: CertBundle | undefined = await readCertBundle(
      infisical,
      { token, projectId, env: ns },
      certKey,
    );
    if (existing && isFresh(existing, cfg.renewWithinDays)) {
      return { apex, action: "skipped", success: true, notAfter: existing.notAfter };
    }

    const zoneId = cfg.cloudflare.zoneIdsByDomain[apex]!;

    // Ensure an ACME account exists (registers + persists on first run only).
    const account = await ensureAccount({
      existingJson: accountJson,
      upsert: async (json) => {
        await infisical.upsertSecret({
          token, projectId, env: ns, key: cfg.paths.account, value: json,
        });
      },
      acmeEnv: cfg.acmeEnv,
      // No fallback: example.com is a forbidden contact domain for Let's Encrypt.
      // ensureAccount omits the contact entirely when email is undefined.
      email: cfg.acmeEmail,
    });

    const bundle = await issueWildcard({
      apex,
      zoneId,
      accountJson: JSON.stringify(account),
      dns,
    });
    await writeCertBundle(infisical, { token, projectId, env: ns }, certKey, bundle);
    return { apex, action: "renewed", success: true, notAfter: bundle.notAfter };
  } catch (err) {
    return { apex, action: "failed", success: false, error: err instanceof Error ? err.message : String(err) };
  }
}
