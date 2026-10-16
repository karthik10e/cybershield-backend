package com.cybershield.cybershield.service;

import com.cybershield.cybershield.dto.EnrichedPacket;
import com.cybershield.cybershield.dto.PacketData;
import com.cybershield.cybershield.dto.PredictionResult;
import com.cybershield.cybershield.model.SecurityIncident;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class TrafficSimulatorService {

    private static final Logger logger = LoggerFactory.getLogger(TrafficSimulatorService.class);

    private final DetectorService detectorService;
    private final ActiveDefenseService activeDefenseService;
    private final TelemetryStatsService telemetryStatsService;
    private final SseStreamingService sseStreamingService;

    private volatile boolean isRunning = true;
    private volatile String attackMode = "mixed";
    private volatile double delay = 0.9;

    private ExecutorService simulatorExecutor;
    private final Random random = new Random();

    private final List<String> botnetIps = new ArrayList<>();
    private final List<String> internalIps = new ArrayList<>();
    private final String victimIp = "192.168.1.10";

    public TrafficSimulatorService(DetectorService detectorService,
                                   ActiveDefenseService activeDefenseService,
                                   TelemetryStatsService telemetryStatsService,
                                   SseStreamingService sseStreamingService) {
        this.detectorService = detectorService;
        this.activeDefenseService = activeDefenseService;
        this.telemetryStatsService = telemetryStatsService;
        this.sseStreamingService = sseStreamingService;

        for (int i = 10; i < 40; i++) botnetIps.add("45.33.32." + i);
        for (int i = 5; i < 30; i++) botnetIps.add("185.220.101." + i);
        for (int i = 20; i < 90; i++) internalIps.add("192.168.1." + i);
    }

    @PostConstruct
    public void init() {
        simulatorExecutor = Executors.newCachedThreadPool();
        start(attackMode, delay);
        logger.info("CyberShield Traffic Simulator initialized in {} mode (delay: {}s)", attackMode, delay);
    }

    @PreDestroy
    public void cleanup() {
        stop();
        if (simulatorExecutor != null) {
            simulatorExecutor.shutdownNow();
        }
    }

    public synchronized void start(String mode, double delaySec) {
        this.attackMode = mode != null ? mode : "mixed";
        this.delay = Math.max(0.1, delaySec);
        this.isRunning = true;

        simulatorExecutor.submit(this::simulationLoop);
    }

    public synchronized void stop() {
        this.isRunning = false;
    }

    public void triggerBurst(String attackType, int count) {
        simulatorExecutor.submit(() -> {
            int burstCount = Math.min(100, Math.max(5, count));
            for (int i = 0; i < burstCount; i++) {
                PacketData pkt = generatePacket(attackType);
                processIncomingPacket(pkt);
                try {
                    Thread.sleep(70);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
    }

    private void simulationLoop() {
        while (isRunning) {
            try {
                PacketData pkt = generatePacket(attackMode);
                processIncomingPacket(pkt);
                Thread.sleep((long) (delay * 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Simulation loop error: {}", e.getMessage());
            }
        }
    }

    public EnrichedPacket processIncomingPacket(PacketData packetData) {
        PredictionResult pred = detectorService.predictPacket(packetData);
        Map<String, Object> meta = packetData.getMeta() != null ? packetData.getMeta() : new HashMap<>();

        String srcIp = (String) meta.getOrDefault("src_ip", "192.168.1.50");
        String dstIp = (String) meta.getOrDefault("dst_ip", victimIp);
        int srcPort = getInt(meta.get("src_port"), 49152 + random.nextInt(10000));
        int dstPort = getInt(meta.get("dst_port"), 80);
        String protocol = (String) meta.getOrDefault("protocol", "TCP");

        SecurityIncident incident = null;
        if (pred.getIsAttack()) {
            incident = activeDefenseService.recordPacket(
                    meta, pred.getAttackType(), pred.getConfidence(),
                    pred.getIsAttack(), pred.getSeverity(), pred.getReasons()
            );
        }

        boolean isBlocked = activeDefenseService.isBlocked(srcIp);

        EnrichedPacket enriched = new EnrichedPacket();
        enriched.setId(telemetryStatsService.getTotalPackets() + 1);
        enriched.setTimestamp(System.currentTimeMillis());
        enriched.setTimeStr(LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
        enriched.setSrcIp(srcIp);
        enriched.setDstIp(dstIp);
        enriched.setSrcPort(srcPort);
        enriched.setDstPort(dstPort);
        enriched.setProtocol(protocol);
        enriched.setService(packetData.getService());
        enriched.setFlag(packetData.getFlag());
        enriched.setAttackType(pred.getAttackType());
        enriched.setIsAttack(pred.getIsAttack());
        enriched.setConfidence(pred.getConfidence());
        enriched.setSeverity(pred.getSeverity());
        enriched.setReasons(pred.getReasons());
        enriched.setIsBlocked(isBlocked);
        enriched.setIncident(incident);

        telemetryStatsService.recordPacket(enriched);
        sseStreamingService.broadcastPacket(enriched);

        return enriched;
    }

    public PacketData generatePacket(String scenario) {
        if ("syn_flood".equalsIgnoreCase(scenario)) return generateSynFlood();
        if ("port_scan".equalsIgnoreCase(scenario)) return generatePortScan();
        if ("brute_force".equalsIgnoreCase(scenario)) return generateBruteForce();
        if ("u2r".equalsIgnoreCase(scenario)) return generateU2R();
        if ("normal_only".equalsIgnoreCase(scenario)) return generateNormal();

        // Mixed mode: 65% normal, 35% various threats
        double r = random.nextDouble();
        if (r < 0.65) return generateNormal();
        if (r < 0.78) return generateSynFlood();
        if (r < 0.88) return generatePortScan();
        if (r < 0.95) return generateBruteForce();
        return generateU2R();
    }

    private PacketData generateNormal() {
        PacketData p = new PacketData();
        p.setDuration(0.05 + random.nextDouble() * 0.4);
        p.setProtocolType("tcp");
        p.setService(random.nextBoolean() ? "http" : "https");
        p.setFlag("SF");
        p.setSrcBytes((long) (200 + random.nextInt(800)));
        p.setDstBytes((long) (1500 + random.nextInt(12000)));
        p.setLoggedIn(1);
        p.setCount(1 + random.nextInt(6));
        p.setSrvCount(1 + random.nextInt(5));
        p.setSerrorRate(0.0);
        p.setRerrorRate(0.0);
        p.setSameSrvRate(0.95);
        p.setDiffSrvRate(0.05);

        Map<String, Object> meta = new HashMap<>();
        meta.put("src_ip", internalIps.get(random.nextInt(internalIps.size())));
        meta.put("dst_ip", victimIp);
        meta.put("src_port", 49152 + random.nextInt(15000));
        meta.put("dst_port", 80);
        meta.put("protocol", "TCP");
        p.setMeta(meta);

        return p;
    }

    private PacketData generateSynFlood() {
        PacketData p = new PacketData();
        p.setDuration(0.0);
        p.setProtocolType("tcp");
        p.setService("http");
        p.setFlag("S0");
        p.setSrcBytes(0L);
        p.setDstBytes(0L);
        p.setCount(350 + random.nextInt(250));
        p.setSrvCount(300 + random.nextInt(200));
        p.setSerrorRate(0.95 + random.nextDouble() * 0.05);
        p.setSameSrvRate(1.0);
        p.setDiffSrvRate(0.0);
        p.setDstHostCount(255);
        p.setDstHostSrvCount(255);

        Map<String, Object> meta = new HashMap<>();
        meta.put("src_ip", botnetIps.get(random.nextInt(botnetIps.size())));
        meta.put("dst_ip", victimIp);
        meta.put("src_port", 1024 + random.nextInt(60000));
        meta.put("dst_port", 80);
        meta.put("protocol", "TCP");
        p.setMeta(meta);

        return p;
    }

    private PacketData generatePortScan() {
        PacketData p = new PacketData();
        p.setDuration(0.02);
        p.setProtocolType("tcp");
        p.setService("other");
        p.setFlag("REJ");
        p.setSrcBytes(0L);
        p.setDstBytes(0L);
        p.setCount(60 + random.nextInt(50));
        p.setSrvCount(1 + random.nextInt(3));
        p.setRerrorRate(0.85);
        p.setSameSrvRate(0.05);
        p.setDiffSrvRate(0.95);
        p.setDstHostCount(255);
        p.setDstHostSrvCount(2);

        int targetPort = List.of(21, 22, 23, 25, 53, 80, 110, 443, 8080, 3306, 3389).get(random.nextInt(11));

        Map<String, Object> meta = new HashMap<>();
        meta.put("src_ip", botnetIps.get(random.nextInt(botnetIps.size())));
        meta.put("dst_ip", victimIp);
        meta.put("src_port", 40000 + random.nextInt(10000));
        meta.put("dst_port", targetPort);
        meta.put("protocol", "TCP");
        p.setMeta(meta);

        return p;
    }

    private PacketData generateBruteForce() {
        PacketData p = new PacketData();
        p.setDuration(2.5 + random.nextDouble() * 2.0);
        p.setProtocolType("tcp");
        p.setService("ssh");
        p.setFlag("SF");
        p.setSrcBytes((long) (300 + random.nextInt(200)));
        p.setDstBytes((long) (150 + random.nextInt(150)));
        p.setNumFailedLogins(3 + random.nextInt(4));
        p.setLoggedIn(0);
        p.setCount(8 + random.nextInt(6));
        p.setSrvCount(8 + random.nextInt(6));
        p.setSameSrvRate(1.0);
        p.setDiffSrvRate(0.0);

        Map<String, Object> meta = new HashMap<>();
        meta.put("src_ip", botnetIps.get(random.nextInt(botnetIps.size())));
        meta.put("dst_ip", victimIp);
        meta.put("src_port", 51000 + random.nextInt(5000));
        meta.put("dst_port", 22);
        meta.put("protocol", "TCP");
        p.setMeta(meta);

        return p;
    }

    private PacketData generateU2R() {
        PacketData p = new PacketData();
        p.setDuration(12.0 + random.nextDouble() * 10.0);
        p.setProtocolType("tcp");
        p.setService("telnet");
        p.setFlag("SF");
        p.setSrcBytes((long) (1200 + random.nextInt(800)));
        p.setDstBytes((long) (3000 + random.nextInt(2000)));
        p.setLoggedIn(1);
        p.setRootShell(1);
        p.setSuAttempted(1);
        p.setNumRoot(3 + random.nextInt(3));
        p.setNumCompromised(2);
        p.setCount(2);
        p.setSrvCount(2);

        Map<String, Object> meta = new HashMap<>();
        meta.put("src_ip", internalIps.get(random.nextInt(internalIps.size())));
        meta.put("dst_ip", victimIp);
        meta.put("src_port", 33000 + random.nextInt(10000));
        meta.put("dst_port", 23);
        meta.put("protocol", "TCP");
        p.setMeta(meta);

        return p;
    }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("is_running", isRunning);
        status.put("mode", attackMode);
        status.put("delay", delay);
        return status;
    }

    private int getInt(Object obj, int defaultVal) {
        if (obj instanceof Number) return ((Number) obj).intValue();
        if (obj instanceof String) {
            try { return Integer.parseInt((String) obj); } catch (Exception ignored) {}
        }
        return defaultVal;
    }
}
