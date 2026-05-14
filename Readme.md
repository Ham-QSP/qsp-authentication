QSP Authentication application is a core module of the QSP platform. 
This application provides OAuth authentication for users. 

# Running this project
## From the sources
### Requirements
- Java 25+
- Maven
- Postgresql 17+

### Setup 
Setup the database connection. As example by environment variable:
```
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/qsp
SPRING_DATASOURCE_USERNAME=qsp
SPRING_DATASOURCE_PASSWORD=qsp_password
```

### Run
Start the application with:
```shell
mvn spring-boot:run -f pom.xml
```

# CI/CD pipeline

The GitHub Actions workflow is defined in `.github/workflows/ci.yaml`.

## Continuous integration

On pull requests targeting `main`, and on pushes to `main` or `ciTest`, the pipeline:

- checks out the sources;
- installs Temurin JDK 25;
- runs Maven verification with `./mvnw --batch-mode --update-snapshots verify`;
- uploads the generated JAR as a workflow artifact.

On pushes to `main`, after the Maven build succeeds, the pipeline also builds and pushes the Docker image:

```text
f4fez/qsp-authentication-server:latest
```

## Release pipeline

Releases are started manually from GitHub Actions with the `Authentication server CI` workflow and the `Run workflow` button on the `main` branch.

The release job:

- configures Git for the GitHub Actions bot;
- runs the Maven Release Plugin with `release:prepare release:perform`;
- updates the project version for the release, commits the next `-SNAPSHOT` version, and creates a Git tag named `v<version>`;
- creates a GitHub Release from the generated tag;
- attaches the generated JAR to the GitHub Release;
- builds and pushes Docker images tagged with the released version and `latest`.

The Docker images pushed during a release are:

```text
f4fez/qsp-authentication-server:<version>
f4fez/qsp-authentication-server:latest
```

## How to create a release

1. Go to the repository on GitHub.
2. Open `Actions`.
3. Select `Authentication server CI`.
4. Click `Run workflow`.
5. Select the `main` branch.
6. Optionally set:
   - `release_version`, for example `1.0.0`;
   - `development_version`, for example `1.0.1-SNAPSHOT`.
7. Start the workflow.

If no version is provided, the Maven Release Plugin uses the current project version without `-SNAPSHOT` as the release version and computes the next development version.

The pipeline requires the following repository secrets to push the Docker image:

```text
DOCKER_HUB_USERNAME
DOCKER_HUB_TOKEN
```

The repository must also allow `GITHUB_TOKEN` to push the release commits and Git tag, and to create the GitHub Release.
