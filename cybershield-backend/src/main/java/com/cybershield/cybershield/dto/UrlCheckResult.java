package com.cybershield.cybershield.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class UrlCheckResult {

    private String url;
    private String domain;

    @JsonProperty("risk_score")
    private Integer riskScore;

    @JsonProperty("risk_level")
    private String riskLevel;

    @JsonProperty("is_https")
    private Boolean isHttps;

    @JsonProperty("is_ip_address")
    private Boolean isIpAddress;

    @JsonProperty("is_suspicious_tld")
    private Boolean isSuspiciousTld;

    private List<String> flags;
    private List<String> recommendations;

    @JsonProperty("scanned_at")
    private Long scannedAt;

    public UrlCheckResult() {
        this.scannedAt = System.currentTimeMillis();
    }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }

    public Integer getRiskScore() { return riskScore; }
    public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public Boolean getIsHttps() { return isHttps; }
    public void setIsHttps(Boolean isHttps) { this.isHttps = isHttps; }

    public Boolean getIsIpAddress() { return isIpAddress; }
    public void setIsIpAddress(Boolean isIpAddress) { this.isIpAddress = isIpAddress; }

    public Boolean getIsSuspiciousTld() { return isSuspiciousTld; }
    public void setIsSuspiciousTld(Boolean isSuspiciousTld) { this.isSuspiciousTld = isSuspiciousTld; }

    public List<String> getFlags() { return flags; }
    public void setFlags(List<String> flags) { this.flags = flags; }

    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }

    public Long getScannedAt() { return scannedAt; }
    public void setScannedAt(Long scannedAt) { this.scannedAt = scannedAt; }
}
