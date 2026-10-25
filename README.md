# cloudflare-acme-worker

Daily Cloudflare Worker that issues and renews wildcard Let's Encrypt
certificates (DNS-01 via Cloudflare DNS) for one or more apex domains and
stores the resulting bundles in Infisical, one folder per domain.

Two `wrangler` envs — staging (weekly, LE-staging) and production (daily, LE-prod).
Both run the same code; the runtime Infisical namespace is selected via the
`INFISICAL_NAMESPACE` CF secret bound per env.

## Setup (one-time)

1. Install deps:
   ```bash
   pnpm install
   ```

2. GitHub repo secrets (for Actions):

   | Secret | Purpose |
   |---|---|
   | `CLOUDFLARE_API_TOKEN` | wrangler-action deploys |
   | `CLOUDFLARE_ACCOUNT_ID` | target CF account |

3. Cloudflare Worker secrets per env:

   ```bash
   # Production (default wrangler deploy)
   wrangler secret put INFISICAL_SERVICE_TOKEN --env production
   wrangler secret put INFISICAL_PROJECT_ID   --env production
   wrangler secret put INFISICAL_NAMESPACE    --env production   # value: prod
   wrangler secret put DEBUG_RENEW_TOKEN      --env production   # optional

   # Staging
   wrangler secret put INFISICAL_SERVICE_TOKEN --env staging
   wrangler secret put INFISICAL_PROJECT_ID    --env staging
   wrangler secret put INFISICAL_NAMESPACE     --env staging    # value: staging
   wrangler secret put DEBUG_RENEW_TOKEN       --env staging    # optional
   ```

4. In each Infisical project (one per env), create:

   | Key | Shape |
   |---|---|
   | `CF_WORKER_CONFIG` | JSON — `acmeEnv` must match the env's LE target (staging/production) |
   | `CF_API_TOKEN` | string — Cloudflare API token with `Zone.DNS:Edit` |
   | `ACME_ACCOUNT` | JSON — created automatically on first run |

   JSON shape: see `src/lib/config.ts` (typed runtime config with validation).

   `paths.cert` = `"certs/<domain>"` is the secret key of the per-domain certificate. The worker writes **one JSON secret per domain** into the `/certs` folder:

   | Secret path | Secret name | Contents |
   |---|---|---|
   | `/certs` | `aribudi.com` | JSON bundle — `apex`, `fullchain`, `privateKey`, `chain` (all raw PEM), `notAfter`, `issuedAt`, `acmeEnv` |

   v4 splits a key on the last `/`: `certs/<domain>` becomes secret path `/certs` + secret name `<domain>`. Secret names may contain dots; secret **paths** may not (alphanumerics, dashes, underscores only), which is why the domain stays in the name and the folder stays `/certs`.

   The renewal check reads that same JSON secret and uses its `notAfter`.

5. Service token needs read/write scope on the secret paths `/` (root-level secrets `CF_WORKER_CONFIG`, `CF_API_TOKEN`, `ACME_ACCOUNT`, `STATUS_LAST_RUN`) and `/certs` (the certificate bundles). It needs **no** folder-create permission — everything is a secret inside the existing `/certs` folder.

## Deployment via GitHub Actions

| Event | Workflow | Outcome |
|---|---|---|
| `pull_request` to main | `ci.yml` | typecheck + test + audit — gate PR merge |
| `push` to main | `ci.yml` + `release-staging.yml` | rc tag `vX.Y.Z-rc.N`, deploy `--env staging`, pre-release in GH Releases |
| Manual `workflow_dispatch` (input: `version`) | `release-production.yml` | promotes chosen rc to stable `vX.Y.Z`, deploy `--env production`, full GH Release |

```bash
git remote add origin <git-url>
git push -u origin main
```

Then create a PR from `feat/<name>` → `main` to start the flow.

## Manual deploy (bypass Actions)

```bash
pnpm exec wrangler deploy                  # production (default)
pnpm exec wrangler deploy --env staging    # staging
```

## Local dev

```bash
pnpm dev                                     # listens on :8787, default --env production
pnpm exec wrangler dev --env staging         # point local dev at staging
```

Trigger scheduled handler manually:
```bash
wrangler dev --test-scheduled
# in another shell:
curl 'http://localhost:8787/__scheduled?cron=0+3+*+*+*'
```

## Tests

```bash
pnpm test         # unit + integration (vitest, runs in worker pool)
pnpm typecheck    # tsc --noEmit
```
