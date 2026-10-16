package com.cybershield.cybershield.dto;

import com.cybershield.cybershield.model.SecurityIncident;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class EnrichedPacket {

    private Long id;
    private Long timestamp;

    @JsonProperty("time_str")
    private String timeStr;

    @JsonProperty("src_ip")
    private String srcIp;

    @JsonProperty("dst_ip")
    private String dstIp;

    @JsonProperty("src_port")
    private Integer srcPort;

    @JsonProperty("dst_port")
    private Integer dstPort;

    private String protocol;
    private String service;
    private String flag;

    @JsonProperty("attack_type")
    private String attackType;

    @JsonProperty("is_attack")
    private Boolean isAttack;

    private Double confidence;
    private String severity;
    private List<String> reasons;

    @JsonProperty("is_blocked")
    private Boolean isBlocked;

    private SecurityIncident incident;

    public EnrichedPacket() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getTimestamp() { return timestamp; }
    public void setTimestamp(Long timestamp) { this.timestamp = timestamp; }

    public String getTimeStr() { return timeStr; }
    public void setTimeStr(String timeStr) { this.timeStr = timeStr; }

    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }

    public String getDstIp() { return dstIp; }
    public void setDstIp(String dstIp) { this.dstIp = dstIp; }

    public Integer getSrcPort() { return srcPort; }
    public void setSrcPort(Integer srcPort) { this.srcPort = srcPort; }

    public Integer getDstPort() { return dstPort; }
    public void setDstPort(Integer dstPort) { this.dstPort = dstPort; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public String getService() { return service; }
    public void setService(String service) { this.service = service; }

    public String getFlag() { return flag; }
    public void setFlag(String flag) { this.flag = flag; }

    public String getAttackType() { return attackType; }
    public void setAttackType(String attackType) { this.attackType = attackType; }

    public Boolean getIsAttack() { return isAttack; }
    public void setIsAttack(Boolean isAttack) { this.isAttack = isAttack; }

    public Double getConfidence() { return confidence; }
    public void setConfidence(Double confidence) { this.confidence = confidence; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public List<String> getReasons() { return reasons; }
    public void setReasons(List<String> reasons) { this.reasons = reasons; }

    public Boolean getIsBlocked() { return isBlocked; }
    public void setIsBlocked(Boolean isBlocked) { this.isBlocked = isBlocked; }

    public SecurityIncident getIncident() { return incident; }
    public void setIncident(SecurityIncident incident) { this.incident = incident; }
}
