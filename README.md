# Authentication Service

Part of the e-commerce microservice application (Innowise Java Advanced course).
The service stores user credentials and issues JWT tokens.

**Status:** the database layer is ready (schema, entities, auditing). Endpoints and token logic
come in the next pull requests.

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

The profile `local` is active by default and holds only the connection defaults. Credentials are
never stored in the repository. The `docker` profile comes with containerization.

## Run locally

Start PostgreSQL in Docker (host port 5434, because 5432 is often taken by a native PostgreSQL):

```
docker run -d --name auth-service-db -p 5434:5432 -e POSTGRES_DB=auth_service_db -e POSTGRES_USER=<user> -e POSTGRES_PASSWORD=<password> -v auth-service-db-data:/var/lib/postgresql postgres:18
```

Set the credentials and start the service.

PowerShell:

```
$env:DB_USERNAME = "<user>"
$env:DB_PASSWORD = "<password>"
.\mvnw.cmd spring-boot:run
```

Bash:

```
export DB_USERNAME=<user> DB_PASSWORD=<password>
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

## Tests

```
./mvnw verify
```

Integration tests start a throwaway PostgreSQL 18 container with Testcontainers, so Docker must be
running. They share one Spring context. To run only the unit tests:

```
./mvnw verify -DexcludedGroups=integration
```
