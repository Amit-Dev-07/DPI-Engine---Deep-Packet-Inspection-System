package com.packetanalyzer.api.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.packetanalyzer.api.dto.AnalysisRequest;
import com.packetanalyzer.api.dto.AnalysisResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AnalyzerService {
    private final ObjectMapper objectMapper;
    private final Path projectRoot;
    private final String executable;
    private final String inputPcap;
    private final String outputPcap;
    private final String reportJson;

    public AnalyzerService(
            ObjectMapper objectMapper,
            @Value("${packet.analyzer.project-root}") String projectRoot,
            @Value("${packet.analyzer.executable}") String executable,
            @Value("${packet.analyzer.input-pcap}") String inputPcap,
            @Value("${packet.analyzer.output-pcap}") String outputPcap,
            @Value("${packet.analyzer.report-json}") String reportJson) {
        this.objectMapper = objectMapper;
        this.projectRoot = Path.of(projectRoot).toAbsolutePath().normalize();
        this.executable = executable;
        this.inputPcap = inputPcap;
        this.outputPcap = outputPcap;
        this.reportJson = reportJson;
    }

    public AnalysisResponse runAnalysis(AnalysisRequest request) throws IOException, InterruptedException {
        List<String> command = buildCommand(request);
        Path logFile = projectRoot.resolve("frontend/dashboard/analyzer-console.log").normalize();
        Files.createDirectories(logFile.getParent());

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(projectRoot.toFile());
        processBuilder.redirectErrorStream(true);
        processBuilder.redirectOutput(logFile.toFile());

        Process process = processBuilder.start();
        boolean completed = process.waitFor(Duration.ofSeconds(90).toSeconds(), TimeUnit.SECONDS);
        String consoleOutput = Files.exists(logFile)
                ? Files.readString(logFile, StandardCharsets.UTF_8)
                : "";

        if (!completed) {
            process.destroyForcibly();
            return new AnalysisResponse(false, "Analysis timed out", command, null, consoleOutput);
        }

        if (process.exitValue() != 0) {
            return new AnalysisResponse(false, "Analyzer failed", command, null, consoleOutput);
        }

        JsonNode report = readReport();
        return new AnalysisResponse(true, "Analysis completed", command, report, consoleOutput);
    }

    public JsonNode getLatestReport() throws IOException {
        return readReport();
    }

    private List<String> buildCommand(AnalysisRequest request) {
        List<String> command = new ArrayList<>();
        command.add(projectRoot.resolve(executable).toString());
        command.add(inputPcap);
        command.add(outputPcap);

        for (String app : request.getBlockApps()) {
            command.add("--block-app");
            command.add(app);
        }

        for (String ip : request.getBlockIps()) {
            command.add("--block-ip");
            command.add(ip);
        }

        for (String domain : request.getBlockDomains()) {
            command.add("--block-domain");
            command.add(domain);
        }

        command.add("--lbs");
        command.add(String.valueOf(request.getLbs()));
        command.add("--fps");
        command.add(String.valueOf(request.getFps()));
        command.add("--json-report");
        command.add(reportJson);

        return command;
    }

    private JsonNode readReport() throws IOException {
        Path reportPath = projectRoot.resolve(reportJson).normalize();
        if (!Files.exists(reportPath)) {
            throw new IOException("JSON report not found: " + reportPath);
        }
        return objectMapper.readTree(Files.readString(reportPath));
    }
}
