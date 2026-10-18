# Authentication Service

Part of the e-commerce microservice application (Innowise Java Advanced course).
The service stores user credentials and issues JWT tokens.

## Run locally

Requires JDK 21.

    ./mvnw spring-boot:run

On Windows use `.\mvnw.cmd`. The service listens on port 8081 (`SERVER_PORT`)
and writes logs to the `logs/` folder (`LOG_DIR`).