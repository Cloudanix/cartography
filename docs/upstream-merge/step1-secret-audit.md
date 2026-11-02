# Step 1 — Secret Audit (tracked-but-gitignored / kept-local files)

Date: 2026-06-03

## Method

Scanned the kept-local files for secret-shaped keys + values, then verified
git-tracked status and searched **entire git history** for each live value.

Files scanned: `dev.py`, `config/default.json`, `config/production.json`,
`Dockerfile.aws.worker`, `Dockerfile.azure.worker`, `proxies.json`,
`scripts/{aws,azure,gcp}.env.{dev,prod}.yml`.

## Headline result

**No secret is in git history.** All 5 live secret values returned `0 commits`
via `git log --all -S`. Therefore: removal + externalization is enough — **no
`filter-repo`/history rewrite required, no forced rotation** (nothing leaked to
git). Rotating these prod creds is still good hygiene but not urgent.

## Live secrets found (all in untracked/gitignored files)

| File:Line | Key | Type | Note |
|---|---|---|---|
| `dev.py:432` | `client_secret` | Azure app client secret | **hardcoded in code** (worst offender) |
| `scripts/azure.env.prod.yml:22` | `CDX_AZURE_CLIENT_SECRET` | Azure app client secret | prod env file |
| `scripts/gcp.env.prod.yml:26` | `CDX_BITBUCKET_CLIENT_SECRET` | Bitbucket OAuth secret | prod env file |
| `scripts/gcp.env.prod.yml:33` | `CDX_GITLAB_CLIENT_SECRET` | GitLab OAuth secret (`gloas-…`) | prod env file (commented dup at :30) |
| `scripts/aws.env.prod.yml:12` | `CDX_SENTRY_DSN` | Sentry DSN | prod env file |
| `scripts/azure.env.prod.yml:6` | `CDX_SENTRY_DSN` | Sentry DSN | prod env file |
| `scripts/gcp.env.prod.yml:5` | `CDX_SENTRY_DSN` | Sentry DSN | prod env file |

`dev.py:431` `client_id` and the `*_CLIENT_ID` values are identifiers, not
secrets, but should still move to config alongside their secret.

### Correction (found during Step 2, missed by first scan — regex lacked `pwd`)

Additional **live secrets** in every `*.env.prod.yml`:

| Key | Type |
|---|---|
| `CDX_APP_NEO4J_PWD` | Neo4j US password (`Piwbiv-…`) |
| `CDX_IN_APP_NEO4J_PWD` | Neo4j India password (`fejboz-…`) |

Also infra-identifying (not credentials, but blanked in templates to avoid leak):
`CDX_APP_NEO4J_URI` / `CDX_IN_APP_NEO4J_URI` (prod server IPs),
`CDX_AWS_ACCOUNT_ID`, `CDX_AWS_SNS_TOPIC_ARN`, `CDX_CROSS_ACCOUNT_ROLE_ARN`,
`CDX_SUBSCRIPTION_ID`. Still 0 occurrences in git history (re-verified).

## False positives (safe — no action)

- `scripts/azure.env.dev.yml:24/26` — literal placeholder strings
  (`"azure-cartography-request-topic-access-key"`), not real keys.
- `dev.py` `token_uri` / `TOKEN_URL` / `access_token` hits — URLs and function
  calls, no embedded secret.
- `Dockerfile.{aws,azure}.worker` — `ARG` defaults are empty `""` or the literal
  `"azure-client-secret"` placeholder; real values injected at build time.
- `scripts/{aws,azure,gcp}.env.dev.yml` — Sentry DSN empty, secrets blank.

## Tracked-status of the kept-local files

| File | Tracked? | In history? |
|---|---|---|
| `dev.py` | no (gitignored) | no |
| `config/` | no (gitignored) | no |
| `Dockerfile.aws.worker` | no (gitignored) | no |
| `Dockerfile.azure.worker` | no (gitignored) | no |
| `scripts/*.env.*.yml` | no (gitignored, dir-level) | no |
| `scripts/download_azure_timing_logs.py` | **yes** | yes (only tracked file under scripts/) |
| `proxies.json` | yes | yes (no secrets) |

## Disposition → feeds Step 2/3

| File | Secrets? | Action |
|---|---|---|
| `dev.py` | yes (`:432` hardcoded) | **Step 2**: replace `:431-432` with env/config read → then committable |
| `config/default.json`, `config/production.json` | no live | committable; optionally templatize |
| `Dockerfile.aws.worker`, `Dockerfile.azure.worker` | no (build-arg pattern already clean) | committable as-is |
| `scripts/*.env.dev.yml` | no live | commit as `.example`/dev template |
| `scripts/*.env.prod.yml` | **yes** | stay local; add `*.env.prod.example.yml` with empty values |
| `proxies.json` | no | already fine |

## Next (Step 2)

1. `dev.py:431-432` — pull `client_id`/`client_secret` from
   `os.environ`/`cartography/config.py` (env names `CDX_AZURE_CLIENT_ID` /
   `CDX_AZURE_CLIENT_SECRET` already exist in the prod yml — reuse them).
2. Add committable templates: `scripts/{aws,azure,gcp}.env.prod.example.yml`
   (keys present, values empty), keep real `*.env.prod.yml` gitignored.
3. Confirm `cartography/config.py` is the single funnel for all `CDX_*` reads.
