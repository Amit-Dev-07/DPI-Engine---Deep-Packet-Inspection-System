# Docker and Render Deployment

This project can run as a single Docker web service:

```text
Browser
  -> Spring Boot REST API
  -> C++ DPI Engine
  -> JSON report
  -> React dashboard
```

The Docker container serves the dashboard from Spring Boot and exposes the REST API under `/api`.

## Local Docker build

From the project root:

```powershell
docker build -t packet-analyzer .
docker run --rm -p 8080:8080 packet-analyzer
```

Open:

```text
http://localhost:8080
```

Health check:

```text
http://localhost:8080/api/health
```

## Render deployment

1. Push the project to GitHub.
2. Go to Render.
3. Create a new Web Service.
4. Select the GitHub repository.
5. Choose Docker runtime.
6. Use:

```text
Dockerfile path: ./Dockerfile
Port: 8080
```

If using `render.yaml`, Render can detect the service automatically.

## Important deployment behavior

- `report.json` is generated inside the container as temporary runtime data.
- The frontend should use same-origin API calls, not hardcoded `localhost`.
- The C++ analyzer runs inside the same container as Spring Boot.
- This avoids cross-service file sharing problems.

## Interview explanation

> I containerized the full system as one Docker web service. The Spring Boot backend serves the React dashboard and exposes REST endpoints. When the user clicks a dashboard mode, Spring Boot executes the C++ DPI engine inside the container, reads the generated JSON report, and returns it to the frontend.
