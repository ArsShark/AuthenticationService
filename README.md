# Authentication Service

Part of the e-commerce microservice application (Innowise Java Advanced course).
The service stores user credentials and issues JWT tokens.

**Status:** the database layer and the internal endpoint that creates accounts are ready. Token
logic (login, refresh, validation, JWKS) comes in the next pull requests.

## Requirements

- JDK 21
- Docker (local database and integration tests)

## Configuration

All settings are environment variables.

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `8081` | HTTP port |
| `LOG_DIR` | `logs` | Directory of the log files |
| `DB_HOST` | `localhost` | Database host (default of the `local` profile) |
| `DB_PORT` | `5434` | Database port (default of the `local` profile) |
| `DB_NAME` | `auth_service_db` | Database name (default of the `local` profile) |
| `DB_USERNAME` | none, required | Database user |
| `DB_PASSWORD` | none, required | Database password |
| `INTERNAL_API_KEY` | none, required | Shared key of the internal endpoints; the service does not start without it |
| `ADMIN_LOGIN` | empty | Login (an email) of the first admin, see below |
| `ADMIN_PASSWORD` | empty | Password of the first admin, see below |

The profile `local` is active by default and holds only the connection defaults. Credentials and
keys are never stored in the repository. The `docker` profile comes with containerization.

## Run locally

Start PostgreSQL in Docker (host port 5434, because 5432 is often taken by a native PostgreSQL):

```
docker run -d --name auth-service-db -p 5434:5432 -e POSTGRES_DB=auth_service_db -e POSTGRES_USER=<user> -e POSTGRES_PASSWORD=<password> -v auth-service-db-data:/var/lib/postgresql postgres:18
```

Set the settings and start the service.

PowerShell:

```
$env:DB_USERNAME = "<user>"
$env:DB_PASSWORD = "<password>"
$env:INTERNAL_API_KEY = "<any long random string>"
.\mvnw.cmd spring-boot:run
```

Bash:

```
export DB_USERNAME=<user> DB_PASSWORD=<password> INTERNAL_API_KEY=<any long random string>
./mvnw spring-boot:run
```

Environment variables set with `$env:` live only in the current PowerShell tab. The service writes
logs to the `logs/` folder.

## Database

PostgreSQL, one database per service. The schema is created by Liquibase at startup
(`src/main/resources/db/changelog/`); Hibernate only validates it (`ddl-auto: validate`).
An applied changeSet is never edited: every schema change is a new file in `changes/`.

| Table | Purpose |
|---|---|
| `credentials` | Login (the email), BCrypt password hash, role (`ADMIN` or `USER`) and the id of the profile in User Service |
| `refresh_tokens` | Issued refresh tokens, stored by their `jti` with an expiry and a revocation time |

Rules that the database enforces itself: unique login, unique profile id, a known role, and a
profile id that may be empty only for an `ADMIN`. Deleting a credential deletes its tokens.

## API

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

Responses (errors are RFC 9457 `application/problem+json`):

| Status | When |
|---|---|
| `201` | Created. The body is `{id, login, role, userId, createdAt}`; it never contains the password or its hash, and there is no `Location` header |
| `400` | The body is invalid. The extension `errors` lists `{field, message}`, sorted by field; rejected values are never echoed |
| `401` | The header `X-Internal-Key` is missing or wrong |
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

## First admin

Registration always creates the role `USER`, so the first admin comes from the environment, which
needs no manual step in a fresh Docker Compose or Kubernetes setup:

- `ADMIN_LOGIN` and `ADMIN_PASSWORD` both empty: no admin is created.
- Only one of them set, or a value that breaks the rules above: the service does not start.
- Both set: the admin (role `ADMIN`, no user profile) is created at startup if the login does not
  exist yet. An existing account is never changed: a new password in the environment does not
  overwrite the old one, and a login that already belongs to a user is not taken over (a warning
  is logged).

## Security notes

- Passwords are hashed with BCrypt (a unique salt per password, the salt is part of the hash).
  Passwords, hashes, logins and keys are never logged, and the `toString()` of the request and the
  settings do not print them.
- The Hibernate logger `org.hibernate.orm.jdbc.error` is set to `ERROR`: at `WARN` it logs the
  whole failing row, including the password hash.
- Duplicates are rejected by the database (UNIQUE constraints), so parallel requests cannot create
  two accounts for one login or one user; a lost race is a `409`, not a `500`.

## Tests

```
./mvnw verify
```

Integration tests start a throwaway PostgreSQL 18 container with Testcontainers, so Docker must be
running. They share one Spring context. To run only the unit tests:

```
./mvnw verify -DexcludedGroups=integration
```
