package com.cybershield.cybershield.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

public class FileScanResponse {

    private String filename;

    @JsonProperty("total_analyzed")
    private Integer totalAnalyzed;

    @JsonProperty("threats_detected")
    private Integer threatsDetected;

    @JsonProperty("safe_count")
    private Integer safeCount;

    @JsonProperty("threat_percentage")
    private Double threatPercentage;

    private Map<String, Integer> breakdown;
    private List<PredictionResult> samples;

    public FileScanResponse() {}

    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }

    public Integer getTotalAnalyzed() { return totalAnalyzed; }
    public void setTotalAnalyzed(Integer totalAnalyzed) { this.totalAnalyzed = totalAnalyzed; }

    public Integer getThreatsDetected() { return threatsDetected; }
    public void setThreatsDetected(Integer threatsDetected) { this.threatsDetected = threatsDetected; }

    public Integer getSafeCount() { return safeCount; }
    public void setSafeCount(Integer safeCount) { this.safeCount = safeCount; }

    public Double getThreatPercentage() { return threatPercentage; }
    public void setThreatPercentage(Double threatPercentage) { this.threatPercentage = threatPercentage; }

    public Map<String, Integer> getBreakdown() { return breakdown; }
    public void setBreakdown(Map<String, Integer> breakdown) { this.breakdown = breakdown; }

    public List<PredictionResult> getSamples() { return samples; }
    public void setSamples(List<PredictionResult> samples) { this.samples = samples; }
}
