package com.cybershield.cybershield.model;

import jakarta.persistence.*;

@Entity
@Table(name = "url_scan_results")
public class UrlScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 1000)
    private String url;

    @Column(length = 255)
    private String domain;

    @Column(name = "risk_score")
    private Integer riskScore;

    @Column(name = "risk_level", length = 32)
    private String riskLevel;

    @Column(name = "is_https")
    private Boolean isHttps;

    @Column(name = "is_ip_address")
    private Boolean isIpAddress;

    @Column(name = "is_suspicious_tld")
    private Boolean isSuspiciousTld;

    @Column(length = 1000)
    private String flags;

    @Column(name = "scanned_at")
    private Long scannedAt;

    public UrlScanResult() {
        this.scannedAt = System.currentTimeMillis();
    }

    public UrlScanResult(String url, String domain, Integer riskScore, String riskLevel,
                         Boolean isHttps, Boolean isIpAddress, Boolean isSuspiciousTld,
                         String flags) {
        this();
        this.url = url;
        this.domain = domain;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.isHttps = isHttps;
        this.isIpAddress = isIpAddress;
        this.isSuspiciousTld = isSuspiciousTld;
        this.flags = flags;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

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

    public String getFlags() { return flags; }
    public void setFlags(String flags) { this.flags = flags; }

    public Long getScannedAt() { return scannedAt; }
    public void setScannedAt(Long scannedAt) { this.scannedAt = scannedAt; }
}
