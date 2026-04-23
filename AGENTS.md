# Repository Guidelines

## Project Structure & Module Organization
This repository is a Kotlin-based Spring Boot authorization server. Application code lives under `src/main/kotlin/fr/f4fez/authorizationserver`, 
with feature packages such as `config` and `authorization`. Runtime configuration is in `src/main/resources`, including `application.yaml` 
and Liquibase changelogs under `src/main/resources/db/changelog`. Tests live in `src/test/kotlin`, with test-only properties in `src/test/resources`. 
Build output is generated in `target/` and should not be edited manually.

## Build, Test, and Development Commands
Use the Maven wrapper so local Maven installation details do not matter.

- `./mvnw spring-boot:run`: start the service locally on port `9000`.
- `./mvnw test`: run the JUnit 5 test suite; current tests use Testcontainers and require Docker.
- `./mvnw package`: compile, test, and build the runnable JAR.
- `./mvnw clean`: remove generated build artifacts from `target/`.

For local development, ensure Java 21 and PostgreSQL are available. Default datasource settings are in `src/main/resources/application.yaml`.

## Coding Style & Naming Conventions
Follow Kotlin conventions already used in the codebase: 4-space indentation, `PascalCase` for classes, `camelCase` for functions and properties, and package names under `fr.f4fez.authorizationserver`. Keep Spring configuration classes in `config` and security/authentication-specific code in feature packages. YAML keys use lowercase dotted or nested naming. No formatter or linter is configured in `pom.xml`, so keep formatting consistent with surrounding code.

## Testing Guidelines
Write tests in `src/test/kotlin` with names ending in `Test`. Prefer Spring Boot integration tests for wiring and security behavior, and keep test configuration in `src/test/resources/application.yaml`. Because the project includes `org.testcontainers:postgresql`, tests should be written to run against PostgreSQL-backed containers when database behavior matters.

## Commit & Pull Request Guidelines
Git history currently starts with a single `Initial commit`, so no strong convention is established yet. Use short, imperative commit subjects such as `Add client properties binding` or `Cover refresh token converter`. For pull requests, include a clear summary, note any database or configuration changes, link related issues, and list the commands you ran locally. Include request/response examples when behavior changes affect authentication flows.

## Security & Configuration Tips
Do not commit real credentials or environment-specific secrets. Treat `application.yaml` values as local defaults only, and prefer environment overrides for deployment settings.
