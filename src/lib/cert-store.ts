import type { CertBundle } from "./acme";
import { InfisicalClient } from "./infisical";

export interface CertStoreTarget {
  token: string;
  projectId: string;
  env: string;
}

/**
 * Store the bundle as ONE JSON secret. Key "certs/<domain>" splits into
 * secret path "/certs" + secret name "<domain>", so each domain gets its
 * own secret inside the one folder the service token can write to.
 */
export async function writeCertBundle(
  infisical: InfisicalClient,
  target: CertStoreTarget,
  key: string,
  bundle: CertBundle,
): Promise<void> {
  await infisical.upsertSecret({ ...target, key, value: JSON.stringify(bundle) });
}

/** Read the stored bundle; undefined when the secret is missing or unparsable. */
export async function readCertBundle(
  infisical: InfisicalClient,
  target: CertStoreTarget,
  key: string,
): Promise<CertBundle | undefined> {
  const raw = await infisical.getSecret({ ...target, key }).catch(() => undefined);
  if (!raw) return undefined;
  try {
    return JSON.parse(raw) as CertBundle;
  } catch {
    return undefined;
  }
}
