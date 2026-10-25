export type AcmeEnv = "production" | "staging";

export interface Paths {
  cert: string;
  account: string;
  status: string;
}

export interface CloudflareCfg {
  accountId?: string;
  zoneIdsByDomain: Record<string, string>;
}

export interface RawConfig {
  apexes: string[];
  acmeEnv: string;
  acmeEmail?: string;
  renewWithinDays?: number;
  cloudflare: CloudflareCfg;
  paths: Paths;
}

export interface ValidatedConfig extends RawConfig {
  acmeEnv: AcmeEnv;
  renewWithinDays: number;
}

export function defaultPaths(): Paths {
  return { cert: "certs/<domain>", account: "ACME_ACCOUNT", status: "STATUS_LAST_RUN" };
}

export function validateConfig(raw: RawConfig): ValidatedConfig {
  if (!Array.isArray(raw.apexes) || raw.apexes.length === 0) {
    throw new Error("apexes must be a non-empty array");
  }
  if (raw.acmeEnv !== "production" && raw.acmeEnv !== "staging") {
    throw new Error(`acmeEnv must be 'production' or 'staging', got '${raw.acmeEnv}'`);
  }
  if (!raw.paths?.cert || !raw.paths?.account || !raw.paths?.status) {
    throw new Error("paths.cert, paths.account, paths.status are required");
  }
  if (!raw.paths.cert.includes("<domain>")) {
    throw new Error("paths.cert must include '<domain>'");
  }
  for (const apex of raw.apexes) {
    if (!raw.cloudflare?.zoneIdsByDomain?.[apex]) {
      throw new Error(`Missing zoneId for apex '${apex}' in cloudflare.zoneIdsByDomain`);
    }
  }
  return {
    ...raw,
    acmeEnv: raw.acmeEnv as AcmeEnv,
    renewWithinDays: raw.renewWithinDays ?? 30,
  };
}

export async function loadConfig(rawJson: string): Promise<ValidatedConfig> {
  const raw = JSON.parse(rawJson) as RawConfig;
  return validateConfig(raw);
}