package com.cybershield.cybershield.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Entity
@Table(name = "quarantined_hosts")
public class QuarantinedHost {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String ip;

    @Column(name = "blocked_at")
    private Long blockedAt;

    @Column(name = "blocked_at_str", length = 32)
    private String blockedAtStr;

    @Column(length = 500)
    private String reason;

    @Column(name = "attack_type", length = 64)
    private String attackType;

    @Column(name = "rule_id", length = 128)
    private String ruleId;

    @Column(name = "netsh_rule", length = 1000)
    private String netshRule;

    @Column(name = "iptables_rule", length = 1000)
    private String iptablesRule;

    @Column(nullable = false)
    private Boolean active = true;

    public QuarantinedHost() {
        this.blockedAt = System.currentTimeMillis();
        this.blockedAtStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    public QuarantinedHost(String ip, String reason, String attackType, String ruleId,
                           String netshRule, String iptablesRule) {
        this();
        this.ip = ip;
        this.reason = reason;
        this.attackType = attackType;
        this.ruleId = ruleId;
        this.netshRule = netshRule;
        this.iptablesRule = iptablesRule;
        this.active = true;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public Long getBlockedAt() { return blockedAt; }
    public void setBlockedAt(Long blockedAt) { this.blockedAt = blockedAt; }

    public String getBlockedAtStr() { return blockedAtStr; }
    public void setBlockedAtStr(String blockedAtStr) { this.blockedAtStr = blockedAtStr; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public String getAttackType() { return attackType; }
    public void setAttackType(String attackType) { this.attackType = attackType; }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }

    public String getNetshRule() { return netshRule; }
    public void setNetshRule(String netshRule) { this.netshRule = netshRule; }

    public String getIptablesRule() { return iptablesRule; }
    public void setIptablesRule(String iptablesRule) { this.iptablesRule = iptablesRule; }

    public Boolean getActive() { return active; }
    public void setActive(Boolean active) { this.active = active; }
}
