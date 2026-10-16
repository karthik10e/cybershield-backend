package com.cybershield.cybershield.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Entity
@Table(name = "security_incidents")
public class SecurityIncident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long timestamp;

    @Column(name = "time_str", length = 32)
    private String timeStr;

    @Column(name = "src_ip", length = 64)
    private String srcIp;

    @Column(name = "dst_ip", length = 64)
    private String dstIp;

    @Column(name = "src_port")
    private Integer srcPort;

    @Column(name = "dst_port")
    private Integer dstPort;

    @Column(length = 32)
    private String protocol;

    @Column(length = 32)
    private String service;

    @Column(length = 32)
    private String flag;

    @Column(name = "attack_type", length = 64)
    private String attackType;

    @Column(name = "is_attack")
    private Boolean isAttack;

    private Double confidence;

    @Column(length = 32)
    private String severity;

    @Column(length = 64)
    private String action;

    @Column(name = "is_blocked")
    private Boolean isBlocked;

    @Column(length = 2000)
    private String reasons;

    public SecurityIncident() {
        this.timestamp = System.currentTimeMillis();
        this.timeStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }

    public SecurityIncident(String srcIp, String dstIp, Integer srcPort, Integer dstPort,
                            String protocol, String attackType, Boolean isAttack,
                            Double confidence, String severity, String action,
                            Boolean isBlocked, String reasons) {
        this();
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
        this.attackType = attackType;
        this.isAttack = isAttack;
        this.confidence = confidence;
        this.severity = severity;
        this.action = action;
        this.isBlocked = isBlocked;
        this.reasons = reasons;
    }

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

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public Boolean getIsBlocked() { return isBlocked; }
    public void setIsBlocked(Boolean isBlocked) { this.isBlocked = isBlocked; }

    public String getReasons() { return reasons; }
    public void setReasons(String reasons) { this.reasons = reasons; }
}
