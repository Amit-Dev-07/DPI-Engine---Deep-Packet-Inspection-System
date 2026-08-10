package com.packetanalyzer.api.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.util.ArrayList;
import java.util.List;

public class AnalysisRequest {
    private List<String> blockApps = new ArrayList<>();
    private List<String> blockIps = new ArrayList<>();
    private List<String> blockDomains = new ArrayList<>();

    @Min(1)
    @Max(16)
    private int lbs = 2;

    @Min(1)
    @Max(16)
    private int fps = 2;

    public List<String> getBlockApps() {
        return blockApps;
    }

    public void setBlockApps(List<String> blockApps) {
        this.blockApps = blockApps == null ? new ArrayList<>() : blockApps;
    }

    public List<String> getBlockIps() {
        return blockIps;
    }

    public void setBlockIps(List<String> blockIps) {
        this.blockIps = blockIps == null ? new ArrayList<>() : blockIps;
    }

    public List<String> getBlockDomains() {
        return blockDomains;
    }

    public void setBlockDomains(List<String> blockDomains) {
        this.blockDomains = blockDomains == null ? new ArrayList<>() : blockDomains;
    }

    public int getLbs() {
        return lbs;
    }

    public void setLbs(int lbs) {
        this.lbs = lbs;
    }

    public int getFps() {
        return fps;
    }

    public void setFps(int fps) {
        this.fps = fps;
    }
}
