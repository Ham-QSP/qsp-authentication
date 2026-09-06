FROM eclipse-temurin:25-jdk AS builder
WORKDIR /builder
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} application.jar
RUN java -Djarmode=tools -jar application.jar extract --layers --destination extracted

FROM eclipse-temurin:25-jre
# Canonical's service manager ships in the base image but is never executed
# here: the entrypoint below runs java directly. Its bundled Go runtime is the
# only thing in this image carrying high severity vulnerabilities, so removing
# it is what lets the image pass the Grype gate in CI.
#
# This does not shrink the image: layers are additive, so the binary still sits
# in the base layer. It is gone from the final filesystem, which is what stops
# it from being executed and from being reported.
RUN rm -f /usr/bin/pebble
WORKDIR /application
COPY --from=builder /builder/extracted/dependencies/ ./
COPY --from=builder /builder/extracted/snapshot-dependencies/ ./
COPY --from=builder /builder/extracted/spring-boot-loader/ ./
COPY --from=builder /builder/extracted/application/ ./
ENTRYPOINT ["java", "-jar", "application.jar"]
