package com.packetanalyzer.api.dto;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

public class AnalysisResponse {
    private boolean success;
    private String message;
    private List<String> command;
    private JsonNode report;
    private String consoleOutput;

    public AnalysisResponse(boolean success, String message, List<String> command, JsonNode report, String consoleOutput) {
        this.success = success;
        this.message = message;
        this.command = command;
        this.report = report;
        this.consoleOutput = consoleOutput;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public List<String> getCommand() {
        return command;
    }

    public JsonNode getReport() {
        return report;
    }

    public String getConsoleOutput() {
        return consoleOutput;
    }
}
