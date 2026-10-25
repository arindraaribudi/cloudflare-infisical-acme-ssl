import * as acme from "acme-client";

// Workers runtime: axios' default "http" adapter is not bundled, and its fetch
// adapter injects `cache: 'default'` which workerd rejects. Force fetch + no-store.
acme.axios.defaults.adapter = "fetch";
acme.axios.defaults.fetchOptions = { cache: "no-store" };

export interface CertBundle {
  apex: string;
  fullchain: string;    // raw PEM (leaf + intermediates)
  privateKey: string;   // raw PEM
  chain: string;        // raw PEM (intermediates only)
  notAfter: string;
  issuedAt: string;
  acmeEnv: "production" | "staging";
}

export interface AccountJson {
  keyPem: string;
  accountUrl: string;
  emails: string[];
  acmeEnv: "production" | "staging";
}

export function isFresh(
  bundle: { notAfter: string } | undefined,
  renewWithinDays: number,
): boolean {
  if (!bundle) return false;
  const exp = Date.parse(bundle.notAfter);
  if (Number.isNaN(exp)) return false;
  return exp - Date.now() > renewWithinDays * 24 * 60 * 60 * 1000;
}

/**
 * Extract the leaf certificate's expiry as an ISO string, or undefined when the
 * PEM cannot be parsed. `readCertificateInfo` decodes only the first
 * certificate of a chain, i.e. the leaf.
 */
export function parseNotAfter(pem: string): string | undefined {
  try {
    return acme.crypto.readCertificateInfo(pem).notAfter.toISOString();
  } catch {
    return undefined;
  }
}

export function buildBundle(input: {
  apex: string;
  fullchainPem: string;
  privateKeyPem: string;
  chainPem: string;
  notAfter: string;
  acmeEnv: "production" | "staging";
}): CertBundle {
  return {
    apex: input.apex,
    fullchain: input.fullchainPem,
    privateKey: input.privateKeyPem,
    chain: input.chainPem,
    notAfter: input.notAfter,
    issuedAt: new Date().toISOString(),
    acmeEnv: input.acmeEnv,
  };
}

export async function ensureAccount(input: {
  existingJson?: string;
  upsert: (json: string) => Promise<void>;
  acmeEnv: "production" | "staging";
  email?: string;
}): Promise<AccountJson> {
  if (input.existingJson) {
    const existing = JSON.parse(input.existingJson) as AccountJson;
    if (existing.acmeEnv !== input.acmeEnv) {
      throw new Error(
        `Existing ACME account has acmeEnv='${existing.acmeEnv}' but config wants '${input.acmeEnv}'`,
      );
    }
    return existing;
  }
  const keyPem = (await acme.crypto.createPrivateKey()).toString();
  const client = new acme.Client({
    directoryUrl: acme.directory.letsencrypt[input.acmeEnv],
    accountKey: keyPem,
  });
  // A contact is optional; Let's Encrypt rejects some domains (e.g. example.com)
  // outright, so an account may be created with no contact field at all.
  await client.createAccount({
    termsOfServiceAgreed: true,
    ...(input.email ? { contact: [`mailto:${input.email}`] } : {}),
  });
  let accountUrl: string | undefined;
  try {
    accountUrl = client.getAccountUrl();
  } catch {
    accountUrl = undefined;
  }
  if (!accountUrl) {
    throw new Error("ACME account URL is missing after account creation");
  }
  const acc: AccountJson = {
    keyPem,
    accountUrl,
    emails: input.email ? [input.email] : [],
    acmeEnv: input.acmeEnv,
  };
  await input.upsert(JSON.stringify(acc));
  return acc;
}

export interface IssueInput {
  apex: string;
  zoneId: string;
  accountJson: string;
  dns: {
    createTxt: (i: { zoneId: string; name: string; content: string }) => Promise<string>;
    deleteTxt: (i: { zoneId: string; recordId: string }) => Promise<void>;
    pollTxtPropagated: (i: { zoneId: string; name: string; content: string }) => Promise<boolean>;
  };
}

export async function issueWildcard(input: IssueInput): Promise<CertBundle> {
  const account = JSON.parse(input.accountJson) as AccountJson;
  const directoryUrl = acme.directory.letsencrypt[account.acmeEnv];

  const privateKey = await acme.crypto.createPrivateKey();
  const privateKeyPem = privateKey.toString();

  const client = new acme.Client({
    directoryUrl,
    accountKey: account.keyPem,
    accountUrl: account.accountUrl,
  });

  // Boulder compares CSR identifiers to order identifiers order-sensitively, so
  // the wildcard must come first (matches the CSR DNS-name order).
  const order = await client.createOrder({
    identifiers: [
      { type: "dns", value: `*.${input.apex}` },
      { type: "dns", value: input.apex },
    ],
  });

  const authzs = await client.getAuthorizations(order);
  const challenges = authzs.map((authz) => {
    const challenge = authz.challenges.find((c) => c.type === "dns-01");
    if (!challenge) {
      throw new Error(`No dns-01 challenge for authorization ${authz.identifier.value}`);
    }
    return { authz, challenge };
  });

  const recordName = `_acme-challenge.${input.apex}`;
  // The wildcard and apex authorizations share one TXT name with different
  // values, so every record has to exist at the same time.
  const records: { id: string; content: string }[] = [];
  try {
    for (const { challenge } of challenges) {
      const content = await client.getChallengeKeyAuthorization(challenge);
      const id = await input.dns.createTxt({
        zoneId: input.zoneId,
        name: recordName,
        content,
      });
      records.push({ id, content });
    }

    for (const { content } of records) {
      const propagated = await input.dns.pollTxtPropagated({
        zoneId: input.zoneId,
        name: recordName,
        content,
      });
      if (!propagated) {
        throw new Error(`DNS-01 TXT did not propagate in time at ${recordName}`);
      }
    }

    // Skip acme-client's local DNS pre-check: it resolves TXT via node:dns,
    // which is unreliable in workerd. pollTxtPropagated already confirmed the
    // record via the Cloudflare API, and the CA validates DNS-01 itself.
    for (const { challenge } of challenges) {
      await client.completeChallenge(challenge);
      await client.waitForValidStatus(challenge);
    }

    const [, csr] = await acme.crypto.createCsr(
      { commonName: `*.${input.apex}`, altNames: [input.apex] },
      privateKey,
    );
    const finalized = await client.finalizeOrder(order, csr);
    await client.waitForValidStatus(finalized);
    const fullchainPem = await client.getCertificate(finalized);

    const blocks = fullchainPem
      .split("-----END CERTIFICATE-----")
      .filter((b) => b.trim())
      .map((b) => `${b.trim()}\n-----END CERTIFICATE-----`);
    // fullchain = leaf + intermediates (nginx needs both); chain = intermediates only.
    const fullchainClean = blocks.join("\n");
    const chainClean = blocks.slice(1).join("\n");

    // ponytail: 60d ceiling sits below Let's Encrypt's current 64d minimum
    // lifetime, so an unparsable cert can never push renewal past real expiry.
    const notAfter =
      parseNotAfter(fullchainPem) ??
      new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString();

    const bundle = buildBundle({
      apex: input.apex,
      fullchainPem: fullchainClean,
      privateKeyPem,
      chainPem: chainClean,
      notAfter,
      acmeEnv: account.acmeEnv,
    });

    return bundle;
  } finally {
    for (const record of records) {
      await input.dns
        .deleteTxt({ zoneId: input.zoneId, recordId: record.id })
        .catch(() => undefined);
    }
  }
}