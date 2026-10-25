# Authentication Service

Part of the e-commerce microservice application (Innowise Java Advanced course).
The service stores user credentials, logs users in and issues, refreshes and validates JWT
tokens. It also publishes the public key that the other services use to verify the tokens.

**Status:** accounts, login, refresh, validation and the public key (JWKS) are ready, and the
service runs in Docker (Dockerfile and Compose file). User Service already verifies the tokens;
the API Gateway starts to use them in its own pull request.

## Requirements

- JDK 21
- Docker (local database, Docker Compose and integration tests)
- OpenSSL, or PowerShell 7, to generate the signing key (see below)

## Configuration

All settings are environment variables.

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `8081` | HTTP port |
| `LOG_DIR` | `logs` | Directory of the log files |
| `DB_HOST` | `localhost` (`local`), `postgres` (`docker`) | Database host |
| `DB_PORT` | `5434` (`local`), `5432` (`docker`) | Database port |
| `DB_NAME` | `auth_service_db` | Database name |
| `DB_USERNAME` | none, required | Database user |
| `DB_PASSWORD` | none, required | Database password |
| `INTERNAL_API_KEY` | none, required | Shared key of the internal endpoints; the service does not start without it |
| `JWT_PRIVATE_KEY` | none, required | RSA private key that signs the tokens, see below; the service does not start without it |
| `JWT_ACCESS_TTL` | `PT15M` | Lifetime of an access token (ISO-8601 duration) |
| `JWT_REFRESH_TTL` | `P7D` | Lifetime of a refresh token (ISO-8601 duration) |
| `JWT_ISSUER` | `authentication-service` | The `iss` claim of every token; the services that verify tokens expect the same value |
| `ADMIN_LOGIN` | empty | Login (an email) of the first admin, see below |
| `ADMIN_PASSWORD` | empty | Password of the first admin, see below |

### Spring profiles

| Profile  | How it is selected                                      | Config file              | PostgreSQL host by default |
|----------|---------------------------------------------------------|--------------------------|----------------------------|
| `local`  | default, used when no profile is set                    | `application-local.yml`  | `localhost`, port `5434`   |
| `docker` | `SPRING_PROFILES_ACTIVE=docker` (set by Docker Compose) | `application-docker.yml` | `postgres` (the Compose service name), port `5432` |

The profile files contain only the datasource URL. Credentials and keys are never stored in them
or anywhere else in the repository. Every value can be overridden by an environment variable.

### The signing key

`JWT_PRIVATE_KEY` is an RSA private key of at least 2048 bits in **PKCS#8 DER** format, encoded as
base64 on **one line**. The public key and the key id are derived from it, so there is nothing
else to configure. Error messages of the service never contain the value.

Bash (OpenSSL; on macOS `base64` has no `-w0` and does not wrap the line, so drop that option):

```
export JWT_PRIVATE_KEY=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0)
```

PowerShell with OpenSSL (it comes with Git for Windows, `C:\Program Files\Git\usr\bin\openssl.exe`).
The key goes through files, because PowerShell 5 damages binary data in a pipe:

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER -out key.der
$env:JWT_PRIVATE_KEY = [Convert]::ToBase64String([IO.File]::ReadAllBytes("key.der"))
Remove-Item key.pem, key.der
```

PowerShell 7 without OpenSSL:

```
$env:JWT_PRIVATE_KEY = [Convert]::ToBase64String([Security.Cryptography.RSA]::Create(2048).ExportPkcs8PrivateKey())
```

Do not use `openssl genpkey -outform DER` on its own: it writes the older PKCS#1 layout, which the
service refuses (the message says so). A new key means a new key id, so every token signed with
the old key stops verifying: generate the key once per environment and keep it in a secret store.

## Run locally

Start PostgreSQL in Docker (host port 5434, because 5432 is often taken by a native PostgreSQL):

```
docker run -d --name auth-service-db -p 5434:5432 -e POSTGRES_DB=auth_service_db -e POSTGRES_USER=<user> -e POSTGRES_PASSWORD=<password> -v auth-service-db-data:/var/lib/postgresql postgres:18
```

Set the settings (generate `JWT_PRIVATE_KEY` as shown above) and start the service.

PowerShell:

```
$env:DB_USERNAME = "<user>"
$env:DB_PASSWORD = "<password>"
$env:INTERNAL_API_KEY = "<any long random string>"
$env:ADMIN_LOGIN = "admin@example.com"
$env:ADMIN_PASSWORD = "<at least 8 characters>"
.\mvnw.cmd spring-boot:run
```

Bash:

```
export DB_USERNAME=<user> DB_PASSWORD=<password> INTERNAL_API_KEY=<any long random string>
export ADMIN_LOGIN=admin@example.com ADMIN_PASSWORD=<at least 8 characters>
./mvnw spring-boot:run
```

Environment variables set with `$env:` live only in the current PowerShell tab. The service writes
logs to the `logs/` folder.

## Run with Docker

### In a Docker container

The image is built from the multi-stage `Dockerfile`: the first stage builds the jar with the
Maven Wrapper (tests are skipped, they are run separately), the second stage contains only a JRE
and the jar. The application runs as a non-root user and writes its logs to `/app/logs`. No key
or password is baked into the image: the signing key is read only when the application starts.

This example uses the PostgreSQL container from "Run locally" (it must be running:
`docker start auth-service-db`) and the variables of that section set in the current shell
(`JWT_PRIVATE_KEY` is generated as shown in "The signing key"):

```powershell
docker build -t authentication-service:dev .

docker run --rm --name authentication-service -p 8081:8081 `
  -e SPRING_PROFILES_ACTIVE=docker `
  -e DB_HOST=host.docker.internal -e DB_PORT=5434 `
  -e DB_USERNAME -e DB_PASSWORD -e INTERNAL_API_KEY -e JWT_PRIVATE_KEY `
  authentication-service:dev
```

`-e DB_USERNAME` without a value passes the variable from the current shell, so the password and
the key stay out of the command line. Stop the service started from the IDE first: both use
port 8081.

### With Docker Compose

`docker-compose.yml` starts the application (built from this repository) and PostgreSQL 18.

```powershell
Copy-Item .env.example .env
# set DB_USERNAME, DB_PASSWORD, INTERNAL_API_KEY and JWT_PRIVATE_KEY in .env
# (the file is ignored by Git)
docker compose up --build -d
docker compose ps
```

`JWT_PRIVATE_KEY` goes into `.env` as one line, without quotes (generate it as shown in "The
signing key"). The placeholder `change-me` is not valid base64 on purpose, so the service refuses
to start until it is replaced. `DB_USERNAME`, `DB_PASSWORD`, `INTERNAL_API_KEY` and
`JWT_PRIVATE_KEY` are required: Compose stops with a message if one is empty. To create the first
admin, set `ADMIN_LOGIN` and `ADMIN_PASSWORD` in `.env` (both or neither, see "First admin"); put
a password that contains `$` or `#` in single quotes.

The service is available at http://localhost:8081. PostgreSQL is reachable only inside the Compose
network (its port is not published); the application waits for its health check. Variables set in
the shell win over `.env`. The data lives in the volume `postgres-data` and the logs in
`app-logs`, so both survive `docker compose down`.

User Service runs in its own Compose project and reaches this service through the host: its
`AUTH_JWKS_URI` is `http://host.docker.internal:8081/.well-known/jwks.json`. In the Compose file
of the whole system the service is called `authentication-service` instead.

Useful commands:

```powershell
docker compose logs app --tail 50                 # application log
docker compose exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
docker compose down                                # stop, keep the data
docker compose down -v                             # stop and delete the data volumes
```

Do not paste the output of `docker compose config` anywhere: it prints the secrets. To only
validate the files, use `docker compose config --quiet`.

## Database

PostgreSQL, one database per service. The schema is created by Liquibase at startup
(`src/main/resources/db/changelog/`); Hibernate only validates it (`ddl-auto: validate`).
An applied changeSet is never edited: every schema change is a new file in `changes/`.

| Table | Purpose |
|---|---|
| `credentials` | Login (the email), BCrypt password hash, role (`ADMIN` or `USER`) and the id of the profile in User Service |
| `refresh_tokens` | Issued refresh tokens, stored by their `jti` with an expiry and a revocation time; the token itself is never stored |

Rules that the database enforces itself: unique login, unique profile id, a known role, and a
profile id that may be empty only for an `ADMIN`. Deleting a credential deletes its tokens.

## API

Errors are RFC 9457 `application/problem+json`. Responses that carry tokens are never cached
(`Cache-Control: no-store`).

| Endpoint | Who may call it |
|---|---|
| `POST /api/auth/login` | Anybody |
| `POST /api/auth/refresh` | Anybody (the refresh token is the credential) |
| `POST /api/auth/validate` | Anybody |
| `GET /.well-known/jwks.json` | Anybody, but meant for the other services: the Gateway does not route it |
| `POST /internal/credentials` | The internal caller only, with `X-Internal-Key` |

### Log in: `POST /api/auth/login`

```json
{"login": "alice@example.com", "password": "s3cret-passw0rd"}
```

| Field | Rules |
|---|---|
| `login` | Required, not blank, at most 255 characters. Stripped and lowercased, like at registration |
| `password` | Required, not blank, at most 1024 characters |

Only the shape is checked. The email format and the password rules of the registration are not
applied: a weak password is just a wrong password and gets the same `401`.

| Status | When |
|---|---|
| `200` | `{"accessToken": "...", "refreshToken": "...", "tokenType": "Bearer", "expiresIn": 900}`; `expiresIn` is the lifetime of the access token in seconds |
| `400` | The body is invalid (`errors` lists `{field, message}`; rejected values are never echoed) |
| `401` | Unknown login, wrong password, or a password longer than 72 bytes. The answer is the same for all of them |

PowerShell:

```
$body = '{"login":"admin@example.com","password":"<ADMIN_PASSWORD>"}'
$tokens = Invoke-RestMethod -Method Post -Uri http://localhost:8081/api/auth/login -ContentType "application/json" -Body $body
```

Bash:

```
curl -s -X POST http://localhost:8081/api/auth/login -H "Content-Type: application/json" \
  -d '{"login":"admin@example.com","password":"<ADMIN_PASSWORD>"}'
```

### Refresh: `POST /api/auth/refresh`

```json
{"refreshToken": "<the refresh token of the last login or refresh>"}
```

The answer has the shape of the login answer: a **new pair** of tokens. The refresh token that was
used stops working, so the client must keep the new one.

| Status | When |
|---|---|
| `200` | A new pair of tokens |
| `400` | The body has no token |
| `401` | The token is not valid for any reason: garbage, expired, an access token, already used, revoked, or the account is gone. The answer is the same for all of them |

The role and the profile id in the new access token are read from the database again, so a change
of a role acts at the next refresh.

### Validate: `POST /api/auth/validate`

```json
{"token": "<an access token>"}
```

A token that is not valid is a normal answer, not an error, and it has no reason:

```json
{"valid": true, "userId": 7, "role": "USER", "expiresAt": "2026-10-23T12:15:00Z"}
```

```json
{"valid": false}
```

`userId` is absent for an admin who has no profile. Only access tokens are valid: a refresh
token, garbage, an expired token and a token with a wrong signature all get `{"valid": false}`.
A body without a token is a `400`. The answer comes from the token alone, with the checks that
every service makes when it verifies a token with the public key; the database is not consulted.

### Public key: `GET /.well-known/jwks.json`

The JSON Web Key Set (RFC 7517) with the public key that verifies the tokens:

```json
{"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "<thumbprint>", "n": "...", "e": "AQAB"}]}
```

The `kid` is the RFC 7638 thumbprint of the key and is also in the header of every token, so a
client finds the key by it. The answer is cacheable for five minutes (`Cache-Control: public,
max-age=300`) and never holds a private part of the key. The path is deliberately not under
`/api`, so the Gateway route that is open to the outside cannot reach it: the other services read
it from the internal address of this service (for example, with Spring Security's `jwk-set-uri`).

### Create an account: `POST /internal/credentials`

An internal endpoint: the API Gateway calls it while it registers a user, before the user has a
token. It is protected by the internal key, not by a JWT:

```
X-Internal-Key: <value of INTERNAL_API_KEY>
```

The path is deliberately **not** under `/api/auth/`: the Gateway route that is open to the
outside can never reach it. A registered account always gets the role `USER`.

Request body:

```json
{"login": "alice@example.com", "password": "s3cret-passw0rd", "userId": 7}
```

| Field | Rules |
|---|---|
| `login` | Required, a well-formed email, at most 255 characters. Stored stripped and in lowercase |
| `password` | Required, not blank, at least 8 characters and at most 72 bytes in UTF-8 (BCrypt looks only at the first 72 bytes) |
| `userId` | Required, positive: the id of the profile in User Service |

Responses:

| Status | When |
|---|---|
| `201` | Created. The body is `{id, login, role, userId, createdAt}`; it never contains the password or its hash, and there is no `Location` header |
| `400` | The body is invalid. The extension `errors` lists `{field, message}`, sorted by field; rejected values are never echoed |
| `401` | The header `X-Internal-Key` is missing or wrong. The answer is the same for both, so a caller learns nothing about the key |
| `403` | The caller is authenticated, but is not the internal caller (for example a user or admin token) |
| `409` | The login is taken, or the user already has an account |
| `500` | Unexpected error, with a generic message |

PowerShell:

```
$headers = @{ "X-Internal-Key" = $env:INTERNAL_API_KEY }
$body = '{"login":"alice@example.com","password":"s3cret-passw0rd","userId":7}'
Invoke-RestMethod -Method Post -Uri http://localhost:8081/internal/credentials -Headers $headers -ContentType "application/json" -Body $body
```

Bash:

```
curl -i -X POST http://localhost:8081/internal/credentials \
  -H "X-Internal-Key: $INTERNAL_API_KEY" -H "Content-Type: application/json" \
  -d '{"login":"alice@example.com","password":"s3cret-passw0rd","userId":7}'
```

## Tokens

Both tokens are JWTs signed with RS256. The header has `alg`, `typ` and the `kid` of the key.
All times come from the application clock, both when a token is issued and when it is checked,
and there is no clock skew: an expired token is expired.

| Claim | Access token | Refresh token |
|---|---|---|
| `sub` | the id of the account | the id of the account |
| `userId` | the id of the profile in User Service; absent for an admin without a profile | not present |
| `role` | `ADMIN` or `USER` (without a `ROLE_` prefix) | not present |
| `email` | the login | not present |
| `jti`, `iss`, `iat`, `exp` | yes | yes |
| `token_type` | `access` | `refresh` |

`token_type` keeps a refresh token from being accepted as an access token and the other way round.
An access token lives 15 minutes and a refresh token 7 days, unless the settings say otherwise.

### How a refresh token is used

A refresh token is valid while its row in `refresh_tokens` exists and has no revocation time. It
can be used **once**:

1. A refresh revokes the used row with one atomic `UPDATE ... WHERE jti = ? AND revoked_at IS NULL`
   and stores a new pair. The database decides who wins when several requests use the same token
   at once: exactly one gets a new pair.
2. If a token that is no longer valid comes again (used, revoked, or unknown to the database), the
   service takes it for a copy and revokes **every** valid refresh token of that account. The
   caller gets the usual `401`, and the user has to log in again. There is no grace period: two
   parallel refreshes with one token end the session, including the new token of the winner.
3. Logging in again always works: only the refresh tokens are revoked, not the account.

An access token is checked without the database, so it cannot be revoked and stays valid until it
expires (at most 15 minutes by default). Expired rows are not deleted yet.

## First admin

Registration always creates the role `USER`, so the first admin comes from the environment, which
needs no manual step in a fresh Docker Compose or Kubernetes setup:

- `ADMIN_LOGIN` and `ADMIN_PASSWORD` both empty: no admin is created.
- Only one of them set, or a value that breaks the rules above: the service does not start.
- Both set: the admin (role `ADMIN`, no user profile) is created at startup if the login does not
  exist yet. An existing account is never changed: a new password in the environment does not
  overwrite the old one, and a login that already belongs to a user is not taken over (a warning
  is logged).

The admin logs in like any user, and its tokens have no `userId`.

## Security model

The service is a stateless API and is closed by default: a request is allowed only if a rule says
so, and everything else is denied before Spring MVC sees it. Each open rule names its HTTP method,
so another method on the same path stays closed.

| Request | Answer |
|---|---|
| `POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/validate` | Allowed for everybody |
| `GET /.well-known/jwks.json` | Allowed for everybody |
| `/internal/**` with the right `X-Internal-Key` | Allowed: the caller gets the role `INTERNAL` |
| `/internal/**` with no key or a wrong key | `401` |
| `/internal/**` by an authenticated caller who is not the internal caller | `403` |
| Any other path or method, anonymous caller | `401`, also when the path does not exist |
| Any other path or method, authenticated caller | `403` |

- There are no sessions, cookies, login forms or CSRF tokens: nothing in this API uses them.
- `401` and `403` are `application/problem+json`, written in the same place as every other error,
  with constant texts: `Authentication is required` and `Access is denied`. A missing key and a
  wrong key, an unknown login and a wrong password, and every kind of bad refresh token get the
  same answer.
- The internal key is checked only under `/internal/`; anywhere else the header means nothing.
- An unknown path is a `401`, not a `404`, so an anonymous caller cannot find out which paths exist.

## Security notes

- Passwords are hashed with BCrypt (a unique salt per password, the salt is part of the hash).
  Passwords, hashes, logins, tokens, `jti` values and keys are never logged, and the `toString()`
  of the request and the settings do not print them. A test runs every endpoint, with successes
  and failures, and searches everything that was logged for each secret of the run.
- A login does the same work for an unknown login and for a wrong password: one BCrypt comparison,
  with a dummy hash for an unknown login, so neither the answer nor the time shows whether a login
  exists.
- BCrypt silently cuts a password at 72 bytes, so a longer password would match the hash of its
  prefix. The registration rejects such passwords and the login refuses them without comparing.
- The private key is read only from the environment, is never logged, and the public key is
  derived from it. The service does not start with a missing, malformed or too short key.
- The internal key is compared in constant time (`MessageDigest.isEqual`) and checked before the
  request body is read, so a wrong key is a `401` even for an invalid body.
- Spring Boot's default user with a random password (it prints the password to the log) is switched
  off: this service checks accounts with its own code.
- The default response headers of Spring Security stay on, for example `X-Content-Type-Options:
  nosniff` and `Cache-Control: no-store` (the key set sets its own `Cache-Control`).
- The Hibernate logger `org.hibernate.orm.jdbc.error` is set to `ERROR`: at `WARN` it logs the
  whole failing row, including the password hash.
- Duplicates are rejected by the database (UNIQUE constraints), so parallel requests cannot create
  two accounts for one login or one user; a lost race is a `409`, not a `500`.

### Known limits

- There is no rate limit or lockout on the login: it is expected at the API Gateway.
- The service does not know what happens to a profile in User Service. A user who is deactivated
  or deleted there can still log in, and their credentials stay here, until the Gateway or an
  event keeps the two in step.
- An access token cannot be revoked before it expires; a deleted account or a changed role is
  noticed at the next refresh.
- There is no key rotation: one key is published. A new key invalidates all tokens.
- Expired refresh tokens stay in the table.

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| Compose stops with `<VARIABLE> is required, see .env.example` | `.env` is missing or the variable is empty: copy `.env.example` to `.env` and set it |
| The application exits with `JWT_PRIVATE_KEY is not valid base64 on one line` | The key is still the placeholder or was split into several lines: generate it as shown in "The signing key" |
| The application exits with `Set both ADMIN_LOGIN and ADMIN_PASSWORD, or neither` | Only one of the two is set: set both or empty both |
| `Connection refused` to `host.docker.internal:5434` | The PostgreSQL container is stopped: `docker start auth-service-db` |
| `UnknownHostException: postgres` outside Docker | The `docker` profile is active, but there is no Compose network: unset `SPRING_PROFILES_ACTIVE` or set `DB_HOST` |
| `password authentication failed` after `DB_PASSWORD` was changed in `.env` | PostgreSQL takes the password only when the volume is empty: `docker compose down -v` (this deletes the data) |
| A change in `.env` has no effect | A variable of the same name is set in the shell and wins over `.env` |
| Port 8081 is already in use | Stop the service started from the IDE or the other container |
| `curl` fails with `Failed to connect to 127.0.0.1 port <unusual port>` while the container runs | The shell has an `http_proxy` variable, so requests to `localhost` go to a proxy: `curl.exe --noproxy "*" ...` |

## Tests

```
./mvnw verify
```

Integration tests start a throwaway PostgreSQL 18 container with Testcontainers, so Docker must be
running. They share one Spring context. The tokens are signed with a key that the tests generate
at runtime; no key is stored in the repository. To run only the unit tests:

```
./mvnw verify -DexcludedGroups=integration
```
