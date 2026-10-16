package com.cybershield.cybershield.service;

import com.cybershield.cybershield.model.QuarantinedHost;
import com.cybershield.cybershield.model.SecurityIncident;
import com.cybershield.cybershield.repository.QuarantinedHostRepository;
import com.cybershield.cybershield.repository.SecurityIncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ActiveDefenseService {

    private static final Logger logger = LoggerFactory.getLogger(ActiveDefenseService.class);

    private final SecurityIncidentRepository incidentRepository;
    private final QuarantinedHostRepository quarantinedHostRepository;

    private final Set<String> whitelist = Set.of("127.0.0.1", "localhost", "::1", "192.168.1.1", "10.0.0.1");
    private final Map<String, Double> ipThreatScores = new ConcurrentHashMap<>();
    private final double autoBlockThreshold = 0.85;

    public ActiveDefenseService(SecurityIncidentRepository incidentRepository,
                                QuarantinedHostRepository quarantinedHostRepository) {
        this.incidentRepository = incidentRepository;
        this.quarantinedHostRepository = quarantinedHostRepository;
    }

    @Transactional
    public SecurityIncident recordPacket(Map<String, Object> meta, String attackType,
                                         Double confidence, Boolean isAttack,
                                         String severity, List<String> reasons) {
        String srcIp = (String) meta.getOrDefault("src_ip", "0.0.0.0");
        String dstIp = (String) meta.getOrDefault("dst_ip", "192.168.1.10");
        Integer srcPort = getInt(meta.get("src_port"), 0);
        Integer dstPort = getInt(meta.get("dst_port"), 80);
        String protocol = (String) meta.getOrDefault("protocol", "TCP");

        if (whitelist.contains(srcIp) || srcIp.startsWith("127.")) {
            return null;
        }

        String action = "MONITORED";
        boolean isBlocked = isBlocked(srcIp);

        if (Boolean.TRUE.equals(isAttack)) {
            Map<String, Double> severityWeights = Map.of(
                    "DoS", 2.5,
                    "Probe", 1.5,
                    "R2L", 3.0,
                    "U2R", 4.0,
                    "Zero-Day Anomaly", 2.5
            );
            double weight = severityWeights.getOrDefault(attackType, 1.5);
            double addedScore = weight * (confidence != null ? confidence : 0.8);
            double currentScore = ipThreatScores.merge(srcIp, addedScore, Double::sum);

            if ((confidence >= autoBlockThreshold || currentScore >= 5.0) && !isBlocked) {
                blockIp(srcIp, "High-threat " + attackType + " detected (confidence: " + (int)(confidence * 100) + "%)", attackType);
                action = "AUTO-BLOCKED";
                isBlocked = true;
            } else {
                action = isBlocked ? "DROPPED_BY_FIREWALL" : "ALERT_FLAGGED";
            }
        } else {
            ipThreatScores.computeIfPresent(srcIp, (k, v) -> Math.max(0.0, v - 0.1));
        }

        String reasonJoined = reasons != null ? String.join("; ", reasons) : "";
        SecurityIncident incident = new SecurityIncident(
                srcIp, dstIp, srcPort, dstPort, protocol, attackType,
                isAttack, confidence, severity, action, isBlocked, reasonJoined
        );

        return incidentRepository.save(incident);
    }

    public boolean isBlocked(String ip) {
        if (ip == null || ip.isBlank() || whitelist.contains(ip)) return false;
        return quarantinedHostRepository.existsByIpAndActiveTrue(ip);
    }

    @Transactional
    public boolean blockIp(String ip, String reason, String attackType) {
        if (ip == null || ip.isBlank() || whitelist.contains(ip)) return false;

        Optional<QuarantinedHost> existing = quarantinedHostRepository.findByIp(ip);
        if (existing.isPresent()) {
            QuarantinedHost host = existing.get();
            host.setActive(true);
            host.setReason(reason);
            host.setAttackType(attackType);
            host.setBlockedAt(System.currentTimeMillis());
            quarantinedHostRepository.save(host);
            logger.info("IP {} re-quarantined: {}", ip, reason);
            return true;
        }

        String ruleId = "RULE-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        String netsh = "netsh advfirewall firewall add rule name=\"CyberShield_Block_" + ip + "\" dir=in action=block remoteip=" + ip;
        String iptables = "iptables -A INPUT -s " + ip + " -j DROP";

        QuarantinedHost host = new QuarantinedHost(ip, reason, attackType, ruleId, netsh, iptables);
        quarantinedHostRepository.save(host);
        logger.warn("Active Defense: Quarantine rule synthesized for {} ({})", ip, attackType);
        return true;
    }

    @Transactional
    public boolean unblockIp(String ip) {
        Optional<QuarantinedHost> hostOpt = quarantinedHostRepository.findByIpAndActiveTrue(ip);
        if (hostOpt.isPresent()) {
            QuarantinedHost host = hostOpt.get();
            host.setActive(false);
            quarantinedHostRepository.save(host);
            ipThreatScores.remove(ip);
            logger.info("IP {} unblocked and restored to monitoring.", ip);
            return true;
        }
        return false;
    }

    public List<QuarantinedHost> getActiveBlockedHosts() {
        return quarantinedHostRepository.findByActiveTrueOrderByIdDesc();
    }

    public List<SecurityIncident> getRecentIncidents(int limit) {
        return incidentRepository.findTop50ByOrderByIdDesc();
    }

    public List<SecurityIncident> getIncidentsForExport() {
        return incidentRepository.findTop500ByOrderByIdDesc();
    }

    public long getBlockedCount() {
        return quarantinedHostRepository.countByActiveTrue();
    }

    private Integer getInt(Object obj, int defaultVal) {
        if (obj instanceof Number) return ((Number) obj).intValue();
        if (obj instanceof String) {
            try { return Integer.parseInt((String) obj); } catch (Exception ignored) {}
        }
        return defaultVal;
    }
}
