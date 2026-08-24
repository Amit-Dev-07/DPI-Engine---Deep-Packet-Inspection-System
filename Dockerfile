# Multi-stage Docker build for Packet Analyzer.
#
# The final container runs one Spring Boot web service that:
# - serves the React dashboard from /
# - exposes the REST API under /api
# - executes the compiled C++ dpi_engine binary inside the same container

FROM ubuntu:22.04 AS cpp-build

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    cmake \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY tests ./tests

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build --target dpi_engine --config Release


FROM maven:3.9-eclipse-temurin-17 AS java-build

WORKDIR /workspace

COPY backend/spring-api/pom.xml ./
COPY backend/spring-api/src ./src
COPY frontend/dashboard ./frontend-dashboard

# Package the dashboard as Spring Boot static content.
RUN mkdir -p src/main/resources/static
RUN cp -r frontend-dashboard/* src/main/resources/static/
RUN mvn -q -DskipTests package


FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

COPY --from=cpp-build /workspace/build/dpi_engine ./dpi_engine
COPY --from=java-build /workspace/target/spring-api-1.0.0.jar ./app.jar
COPY test_dpi.pcap ./test_dpi.pcap

RUN mkdir -p /app/frontend/dashboard /tmp/packet-analyzer
RUN chmod +x /app/dpi_engine

ENV SPRING_PROFILES_ACTIVE=docker
ENV PORT=8080

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]
