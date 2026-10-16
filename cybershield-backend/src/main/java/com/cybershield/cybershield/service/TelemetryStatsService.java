package com.cybershield.cybershield.service;

import com.cybershield.cybershield.dto.EnrichedPacket;
import com.cybershield.cybershield.dto.TelemetryStats;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class TelemetryStatsService {

    private final long startTime = System.currentTimeMillis();
    private final AtomicLong totalPackets = new AtomicLong(0);
    private final AtomicLong totalThreats = new AtomicLong(0);

    private final Map<String, AtomicLong> attacksByType = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> protocolDistribution = new ConcurrentHashMap<>();

    private final Deque<EnrichedPacket> recentPackets = new ConcurrentLinkedDeque<>();
    private static final int MAX_RECENT = 100;

    public TelemetryStatsService() {
        attacksByType.put("DoS", new AtomicLong(0));
        attacksByType.put("Probe", new AtomicLong(0));
        attacksByType.put("R2L", new AtomicLong(0));
        attacksByType.put("U2R", new AtomicLong(0));
        attacksByType.put("Zero-Day Anomaly", new AtomicLong(0));

        protocolDistribution.put("TCP", new AtomicLong(0));
        protocolDistribution.put("UDP", new AtomicLong(0));
        protocolDistribution.put("ICMP", new AtomicLong(0));
    }

    public void recordPacket(EnrichedPacket packet) {
        totalPackets.incrementAndGet();

        String proto = packet.getProtocol() != null ? packet.getProtocol().toUpperCase() : "TCP";
        protocolDistribution.computeIfAbsent(proto, k -> new AtomicLong(0)).incrementAndGet();

        if (Boolean.TRUE.equals(packet.getIsAttack())) {
            totalThreats.incrementAndGet();
            String atk = packet.getAttackType() != null ? packet.getAttackType() : "Unknown";
            attacksByType.computeIfAbsent(atk, k -> new AtomicLong(0)).incrementAndGet();
        }

        recentPackets.addFirst(packet);
        while (recentPackets.size() > MAX_RECENT) {
            recentPackets.removeLast();
        }
    }

    public List<EnrichedPacket> getRecentPackets(int limit) {
        List<EnrichedPacket> list = new ArrayList<>();
        int count = 0;
        for (EnrichedPacket p : recentPackets) {
            list.add(p);
            count++;
            if (count >= limit) break;
        }
        return list;
    }

    public TelemetryStats getStats(long blockedCount, Map<String, Object> simulatorStatus) {
        TelemetryStats stats = new TelemetryStats();
        long uptime = (System.currentTimeMillis() - startTime) / 1000;
        stats.setUptimeSeconds(uptime);

        long total = totalPackets.get();
        long threats = totalThreats.get();
        stats.setTotalPackets(total);
        stats.setTotalThreats(threats);

        double threatRate = total > 0 ? (double) Math.round(((double) threats / total) * 10000.0) / 100.0 : 0.0;
        stats.setThreatRatePercent(threatRate);

        Map<String, Long> atkMap = new HashMap<>();
        attacksByType.forEach((k, v) -> atkMap.put(k, v.get()));
        stats.setAttacksByType(atkMap);

        Map<String, Long> protoMap = new HashMap<>();
        protocolDistribution.forEach((k, v) -> protoMap.put(k, v.get()));
        stats.setProtocolDistribution(protoMap);

        stats.setBlockedIpsCount(blockedCount);
        stats.setSimulator(simulatorStatus);

        Map<String, Object> sniffer = new HashMap<>();
        sniffer.put("status", "Emulated Raw Socket Mode Active");
        sniffer.put("is_running", true);
        sniffer.put("last_error", null);
        stats.setSniffer(sniffer);

        return stats;
    }

    public long getTotalPackets() {
        return totalPackets.get();
    }
}
