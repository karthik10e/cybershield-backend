package com.cybershield.cybershield.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public class TelemetryStats {

    @JsonProperty("uptime_seconds")
    private Long uptimeSeconds;

    @JsonProperty("total_packets")
    private Long totalPackets;

    @JsonProperty("total_threats")
    private Long totalThreats;

    @JsonProperty("threat_rate_percent")
    private Double threatRatePercent;

    @JsonProperty("attacks_by_type")
    private Map<String, Long> attacksByType;

    @JsonProperty("protocol_distribution")
    private Map<String, Long> protocolDistribution;

    @JsonProperty("blocked_ips_count")
    private Long blockedIpsCount;

    private Map<String, Object> simulator;
    private Map<String, Object> sniffer;

    public TelemetryStats() {}

    public Long getUptimeSeconds() { return uptimeSeconds; }
    public void setUptimeSeconds(Long uptimeSeconds) { this.uptimeSeconds = uptimeSeconds; }

    public Long getTotalPackets() { return totalPackets; }
    public void setTotalPackets(Long totalPackets) { this.totalPackets = totalPackets; }

    public Long getTotalThreats() { return totalThreats; }
    public void setTotalThreats(Long totalThreats) { this.totalThreats = totalThreats; }

    public Double getThreatRatePercent() { return threatRatePercent; }
    public void setThreatRatePercent(Double threatRatePercent) { this.threatRatePercent = threatRatePercent; }

    public Map<String, Long> getAttacksByType() { return attacksByType; }
    public void setAttacksByType(Map<String, Long> attacksByType) { this.attacksByType = attacksByType; }

    public Map<String, Long> getProtocolDistribution() { return protocolDistribution; }
    public void setProtocolDistribution(Map<String, Long> protocolDistribution) { this.protocolDistribution = protocolDistribution; }

    public Long getBlockedIpsCount() { return blockedIpsCount; }
    public void setBlockedIpsCount(Long blockedIpsCount) { this.blockedIpsCount = blockedIpsCount; }

    public Map<String, Object> getSimulator() { return simulator; }
    public void setSimulator(Map<String, Object> simulator) { this.simulator = simulator; }

    public Map<String, Object> getSniffer() { return sniffer; }
    public void setSniffer(Map<String, Object> sniffer) { this.sniffer = sniffer; }
}
