# API Synthetic Data

Generates **synthetic request data from your API definitions**. Point it at an OpenAPI/Swagger spec, a Postman collection, or a live API URL. For every endpoint it produces:

| Kind | What it is | Expected API response |
|---|---|---|
| **valid** | Realistic data that satisfies every rule in the schema. `valid-1` has only the required fields and `valid-2` has every field, on every run, so bugs triggered by an optional field being absent or present are found consistently. Later valid cases mix optional fields randomly | `2xx` |
| **boundary** | Values exactly on a limit (`minLength`, `maximum`, `maxItems`, …) | `2xx` |
| **invalid** | Each case breaks **exactly one** rule: missing required field, wrong type, null, bad enum, too short/long, pattern, format, out of range, not a multiple, too few/many items, duplicates, unknown property, missing/wrong body, bad parameters | `4xx` |
| **hostile** *(opt-in)* | Schema-valid but nasty strings: SQL injection, XSS, unicode, path traversal | not `5xx` |

You can write the cases as JSON, JSONL, CSV, a Postman collection, or a suite for the [api-test-framework](#run-the-data-against-your-api) that sends them to your API.

```bash
pip install -r requirements.txt
python -m apisynth generate --openapi https://api.example.com/v3/api-docs -o synthetic-data
```

## Test any API in one command

```bash
python -m apisynth test https://petstore3.swagger.io --api-key special-key
```

Give it the API's base URL, its spec or Swagger UI URL, a Postman collection, or a spec file. It does the rest:

1. **Finds the spec:** it tries the given URL, links on a Swagger UI/Redoc page, then common locations (`/openapi.json`, `/v3/api-docs`, `/swagger.json`, `/api/v3/openapi.json`, …). `$ref`s into other files or URLs are followed.
2. **Works out the base URL** from the spec. Relative `servers` such as `/api/v3` are resolved against where the spec came from. `--base-url` overrides it.
3. **Generates the cases** (valid, boundary and invalid) and calls the API, creating records first and then reusing their real IDs for `GET /pets/{petId}`, `PUT` and `DELETE`.
4. **Reports** in the console, `report.md`, `report.json` and `junit.xml` (in `api-test-report/`), and exits 1 if it found bugs.

| Verdict | Meaning |
|---|---|
| **Authentication not enforced** | a secured endpoint accepted a request with no or invalid credentials |
| **Server error** | 5xx for valid or invalid input |
| **Validation gap** | invalid data accepted (2xx) |
| **Valid data rejected** | 4xx for data the spec allows |
| **Needs attention** (not bugs) | 401/403 (credentials), 404 for a valid request (record missing), 429, network errors |
| **Skipped** | no suitable record to use, or not allowed by the mode |

**Safe on APIs you don't own** (default `--mode safe`):
- **Only its own records:** PUT/PATCH/DELETE, and POSTs to an existing record's sub-path, touch only records **this run created**. Updates that name the record in the body (e.g. `PUT /pet {"id": …}`) are aimed at those records too.
- **Polite:** requests are rate-limited (`--rps 5`), and 429 responses are retried, honouring `Retry-After`.
- **No hostile strings by default:** SQL-injection/XSS cases are only sent with `--hostile`, for APIs you're allowed to security-test.
- **Other modes:** `--mode read` sends only GETs. `--mode all` may change existing records; use it on your own test environment.

### Authentication

Each endpoint uses the scheme(s) its spec declares, including alternatives ("API key **or** OAuth") and combinations ("API key **and** bearer"); the agent picks the alternative you have credentials for. Endpoints with no security info (Postman without auth, live URLs) get whatever you pass.

| Scheme | Options |
|---|---|
| Bearer / JWT | `--token` |
| API key in header, query or cookie | `--api-key` (name and location from the spec; `--api-key-name`, `--api-key-in` to override) |
| HTTP Basic / Digest | `--basic USER:PASS`, `--digest USER:PASS` |
| OAuth 2.0 client credentials | `--client-id`, `--client-secret` (token URL and scopes from the spec, or `--token-url`, `--scope`, `--audience`) |
| OAuth 2.0 password grant | `--username`, `--password` (+ client id/secret if the server needs them) |
| OAuth 2.0 refresh token | `--refresh-token` |
| OAuth 2.0 authorization code / implicit | these need a browser login: get a token there and pass `--token` |
| OpenID Connect | as OAuth: the token endpoint is discovered from the spec's `openIdConnectUrl` |
| Login endpoint | `--login "POST /auth/login"` with `--username/--password` or `--login-body JSON`. The token in the response is found automatically (or set `--login-token-path $.data.token`, `--login-header`), or the session cookie it sets is kept |
| Session cookie | `--cookie "sid=..."` |
| Mutual TLS | `--cert`, `--cert-key`, `--ca-bundle` |
| AWS Signature V4 | `--aws-sigv4 us-east-1/execute-api` with `--aws-access-key/--aws-secret-key/--aws-session-token` or the standard `AWS_*` variables |
| Anything else | `-H "Name: value"` |

- **OAuth tokens** are fetched, cached and renewed automatically: on expiry, or when the API answers 401. Renewal uses the refresh token after a password grant.
- **Secrets from the environment:** any secret can be written as `env:VAR_NAME`, e.g. `--client-secret env:API_CLIENT_SECRET`, so it stays out of shell history and CI logs.
- **Secrets never appear in reports:** authorization headers, cookies, API keys (including in query strings) and signatures are masked.

**Authentication is tested too.** Every endpoint the spec marks as secured is also called **with no credentials** and **with invalid credentials** (a wrong token, key, password or signature). If either succeeds, it's reported as **Authentication not enforced**:
- the checks reuse a valid request that succeeded, so a refusal can only be about the credentials
- for DELETE, the checks run while the record still exists
- turn them off with `--no-auth-tests`

Against the public Petstore, this found that none of the secured pet endpoints enforce their declared API key / OAuth2.

**Records it can't create:** `--param username=user1` tells it which existing record to use.

**Consistent results:** every run includes a "required fields only" and an "every field" valid case, so findings don't depend on the random seed. Two runs against the Petstore with different seeds gave the same verdict for 205 of 207 cases. Add `--seed N` for byte-identical data.

## Sources

Any combination of sources works, and each option can be repeated.

```bash
# OpenAPI 3.0 / 3.1 or Swagger 2.0, JSON or YAML, from a file or URL
python -m apisynth generate --openapi specs/orders.yaml
python -m apisynth generate --openapi https://api.example.com/v3/api-docs -H "Authorization: Bearer $TOKEN"

# Postman collection: request shapes are inferred from the example bodies
python -m apisynth generate --postman MyApi.postman_collection.json

# Live API URL: GET it, infer the record shape from the response, generate payloads for POST <path without id>
python -m apisynth generate --url https://api.example.com/users/42
python -m apisynth generate --url "https://api.example.com/users/42 -> PUT /users/{id}"   # choose the target

# A sample JSON payload or response you already have
python -m apisynth generate --sample saved-response.json --sample "order.json -> POST /orders"
```

**How each source is read**
- **OpenAPI:** `$ref` (including recursive), `allOf`, `oneOf`/`anyOf` with `discriminator`, `nullable`, `readOnly` (never sent), `enum`/`const`, `pattern` (generates matching strings), `format`, numeric ranges including exclusive bounds and `multipleOf`, array limits and `uniqueItems`, `additionalProperties`, path/query/header parameters, and JSON, form and multipart bodies.
- **Postman and live URLs:** the schema is inferred from the examples:
  - formats such as email, uuid, date, date-time, uri and ipv4 are detected
  - fields present in every example become required
  - repeated values become enums
  - server-generated fields (`id`, `createdAt`, `version`, …) are left out of request payloads
  - with several examples of the same endpoint, inference gets better, e.g. at spotting optional fields

  Because these rules are guesses, negative cases from inferred schemas say so in their description.

Use `python -m apisynth endpoints <sources>` to see what was found, and `python -m apisynth infer <sources>` to print the inferred JSON Schema.

## Options

```bash
python -m apisynth generate --openapi spec.yaml \
  -n 10                     # valid requests per endpoint (default 5)
  --seed 42                 # reproducible output (default: random, printed)
  --include "POST /orders*" --exclude "* /admin/*" --tag customers   # pick endpoints (glob or operationId)
  --methods POST,PUT,PATCH  # default: every endpoint that has a body or parameters
  --param userId=42         # pin a parameter to a record that exists (repeatable); only its invalid cases vary it
  --hostile                 # add SQL-injection / XSS / unicode strings
  --no-invalid --no-boundary
  --optional-rate 0.7       # chance each optional field is included in valid data
  --max-invalid 200         # cap per endpoint
  --prefer-examples         # use the spec's example values when present
  -f json,jsonl,csv,apitest,postman   # output formats (default json)
  -o synthetic-data         # output directory
  --base-url https://qa.example.com   # default base URL in the apitest/postman exports (default: spec servers)
  --auth auto               # auth in the exports: auto (from the spec), none, bearer, basic, apikey:<Header>
  --strict                  # exit 1 if the self-check finds a problem (for CI)
```

## Output

```
synthetic-data/
  index.json                        endpoints, counts and the seed
  endpoints/POST_orders.json        all cases for one endpoint (format: json)
  cases.jsonl                       one case per line, all endpoints (format: jsonl)
  csv/POST_orders.valid.csv         valid/boundary data flattened to columns (format: csv)
  csv/POST_orders.negative.csv      invalid/hostile cases with rule, target and body
  <name>.api.yaml                   runnable suite for api-test-framework (format: apitest)
  <name>.postman_collection.json    runnable Postman collection with status checks (format: postman)
```

An example case:

```json
{
  "id": "pattern:body.address.postalCode",
  "kind": "invalid",
  "category": "pattern",
  "target": "body.address.postalCode",
  "description": "body.address.postalCode: \"\" does not match /^[0-9]{5}(-[0-9]{4})?$/",
  "expect": "4xx",
  "request": {"method": "POST", "path": "/customers", "url": "/customers", "body": {"...": "..."}}
}
```

## Run the data against your API

**Using the api-test-framework (pytest):**

```bash
python -m apisynth generate --openapi spec.yaml -f apitest -o generated --name orders
cp generated/orders.api.yaml ../api-test-framework/suites/
cd ../api-test-framework && pytest suites/orders.api.yaml --env qa
```

Each endpoint and kind becomes a data-driven test, and any case your API handles wrongly fails with the full request and response.

- **Base URL:** the spec's `servers` URL is only a default. `--env qa` (from `environments/qa.yaml`) or `--base-url https://qa.example.com` overrides it.
- **Auth:** added automatically from the spec's `securitySchemes` and `security`. Public endpoints (`security: []`) get none. Credentials stay variables, so you pass them at run time: `--var token=...` for bearer/OAuth2, `--var username=... --var password=...` for basic, `--var apiKey=...` for API keys, or put them in the environment file.
- **Choosing auth yourself:** use `--auth bearer|basic|apikey:<Header-Name>|none`, e.g. for Postman/URL sources that have no security info.

**Using Postman/Newman:** `-f postman`, then import the collection or run it with `newman run generated/orders.postman_collection.json --env-var baseUrl=https://qa.example.com --env-var token=...`. Auth is set per request the same way.

**What to expect from the results:**
- **An invalid case that gets a 2xx** is a validation gap in the API: it accepts data its own contract says is wrong.
- **A hostile case that gets a 5xx** is a robustness bug.

**Record IDs:** synthetic data can't know which records exist in your environment, so valid calls to endpoints like `GET /users/{userId}` would get 404. Pin those parameters to real records with `--param userId=42`. DELETE endpoints get one valid case, because a record can only be deleted once.

**Unique fields:** valid data is new for every seed. If you re-send the *same* seed to an environment that keeps data, fields with uniqueness constraints (emails, SKUs) will get 409 Conflict. Use the default random seed per run, or reset the environment.

## How data stays realistic and safe

- **Realistic values from field names:** the field name picks the kind of value (`email`, `firstName`, `phone`, `city`, `country`, `postalCode`, `price`, `quantity`, `createdAt`, `iban`, `expiry`, …). An ambiguous `name` depends on the resource: a person on `/customers`, a product on `/products`, a company on `/suppliers`.
- **Constraints always win:** if a realistic value doesn't fit the schema's pattern or length, a pattern-generated value is used instead.
- **Observed values are reused:** values seen in spec `example`s or real responses (e.g. `role: ADMIN`) are reused when nothing better is known.
- **Fictional contact data:** `example.*` email domains, phone numbers in the 555 range, IPs from documentation ranges, and public payment-gateway test card numbers.
- **Reproducible:** the same seed always produces the same data.

## Self-check

Every run validates its own output against the endpoint schema with an independent JSON Schema validator:
- every valid, boundary and hostile case must **pass** the schema
- every invalid case must **fail** it

If anything doesn't, the run prints the problems. `--strict` turns that into a failing exit code. The test suite runs this check across several spec styles and many seeds.

## Use as a library

```python
from apisynth import Sources, Options, load_endpoints, generate_cases, Generator

endpoints, base_url = load_endpoints(Sources(openapi=["spec.yaml"]))
results, problems, seed = generate_cases(endpoints, Options(seed=42, count=3, hostile=True))
for endpoint, cases in results:
    for case in cases:
        print(endpoint.key, case.kind, case.id, case.request.url(), case.request.body)

# Or one realistic payload for a test:
gen = Generator(seed=1)
body = gen.request(next(e for e in endpoints if e.key == "POST /orders")).body
```

## CI

- **Jenkins:** [`Jenkinsfile`](Jenkinsfile) runs the self-tests, then generates data from `SPEC` (a file or URL parameter), runs it with `--strict`, and archives `synthetic-data/`.
- **GitHub Actions:** [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the self-tests and the example generation on Python 3.11 and 3.13. The test suite has also been run on 3.9, 3.10 and 3.12; GitHub's current runners no longer provide 3.9 or 3.10.

## Project layout

```
apisynth/
  sources/      openapi.py, postman.py, live.py (URLs + sample files)
  schema.py     $ref/allOf handling and OpenAPI -> JSON Schema "request view"
  infer.py      JSON examples -> JSON Schema
  generate.py   valid values (seeded; semantics, patterns, formats, ranges)
  negative.py   invalid / boundary / hostile cases
  semantics.py  realistic values from field names
  verify.py     self-check against the schema
  output.py     json, jsonl, csv, apitest, postman writers
examples/       shop-api.openapi.yaml, inventory.postman_collection.json, employees-response.json
selftests/      pytest suite (pytest)
```

## Limitations

- **External `$ref`s** (to other files or URLs) aren't followed. Bundle the spec into one file first, e.g. with `redocly bundle`.
- **Cross-field rules** that JSON Schema can't express aren't known, e.g. "endDate after startDate" or "state must match country". Add those cases by hand in your test suite.
- **XML bodies** aren't generated.
