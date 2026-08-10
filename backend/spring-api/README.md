# Packet Analyzer REST API

Spring Boot REST API for running the C++ DPI engine from the React dashboard.

## Run

From `backend/spring-api`:

```powershell
mvn spring-boot:run
```

Health check:

```text
http://localhost:8080/api/health
```

Latest report:

```text
http://localhost:8080/api/report
```

Run analyzer:

```http
POST http://localhost:8080/api/analyze
Content-Type: application/json

{
  "blockApps": ["YouTube", "TikTok"],
  "blockIps": ["192.168.1.50"],
  "blockDomains": ["facebook"],
  "lbs": 2,
  "fps": 2
}
```

The API executes `dpi_engine.exe`, generates `frontend/dashboard/report.json`, and returns the parsed JSON report.
