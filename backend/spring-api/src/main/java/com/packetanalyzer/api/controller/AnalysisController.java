package com.packetanalyzer.api.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.packetanalyzer.api.dto.AnalysisRequest;
import com.packetanalyzer.api.dto.AnalysisResponse;
import com.packetanalyzer.api.service.AnalyzerService;
import jakarta.validation.Valid;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class AnalysisController {
    private final AnalyzerService analyzerService;

    public AnalysisController(AnalyzerService analyzerService) {
        this.analyzerService = analyzerService;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of(
                "status", "UP",
                "service", "packet-analyzer-rest-api",
                "timestamp", Instant.now().toString());
    }

    @GetMapping("/report")
    public ResponseEntity<?> latestReport() {
        try {
            JsonNode report = analyzerService.getLatestReport();
            return ResponseEntity.ok(report);
        } catch (IOException ex) {
            return ResponseEntity.status(404).body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/analyze")
    public ResponseEntity<AnalysisResponse> analyze(@Valid @RequestBody AnalysisRequest request) {
        try {
            AnalysisResponse response = analyzerService.runAnalysis(request);
            return ResponseEntity.status(response.isSuccess() ? 200 : 500).body(response);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return ResponseEntity.status(500).body(
                    new AnalysisResponse(false, ex.getMessage(), null, null, ""));
        } catch (IOException ex) {
            return ResponseEntity.status(500).body(
                    new AnalysisResponse(false, ex.getMessage(), null, null, ""));
        }
    }
}
