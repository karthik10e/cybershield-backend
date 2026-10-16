package com.cybershield.cybershield.controller;

import com.cybershield.cybershield.dto.*;
import com.cybershield.cybershield.model.SecurityIncident;
import com.cybershield.cybershield.service.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ApiController {

    private final DetectorService detectorService;
    private final ActiveDefenseService activeDefenseService;
    private final TelemetryStatsService telemetryStatsService;
    private final TrafficSimulatorService trafficSimulatorService;
    private final SseStreamingService sseStreamingService;
    private final UrlSecurityService urlSecurityService;
    private final ObjectMapper objectMapper;

    public ApiController(DetectorService detectorService,
                         ActiveDefenseService activeDefenseService,
                         TelemetryStatsService telemetryStatsService,
                         TrafficSimulatorService trafficSimulatorService,
                         SseStreamingService sseStreamingService,
                         UrlSecurityService urlSecurityService,
                         ObjectMapper objectMapper) {
        this.detectorService = detectorService;
        this.activeDefenseService = activeDefenseService;
        this.telemetryStatsService = telemetryStatsService;
        this.trafficSimulatorService = trafficSimulatorService;
        this.sseStreamingService = sseStreamingService;
        this.urlSecurityService = urlSecurityService;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/stats")
    public ResponseEntity<TelemetryStats> getStats() {
        long blockedCount = activeDefenseService.getBlockedCount();
        Map<String, Object> simStatus = trafficSimulatorService.getStatus();
        return ResponseEntity.ok(telemetryStatsService.getStats(blockedCount, simStatus));
    }

    @GetMapping("/packets/recent")
    public ResponseEntity<List<EnrichedPacket>> getRecentPackets(@RequestParam(value = "limit", defaultValue = "40") int limit) {
        return ResponseEntity.ok(telemetryStatsService.getRecentPackets(limit));
    }

    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamPackets() {
        return sseStreamingService.createEmitter();
    }

    @PostMapping("/predict")
    public ResponseEntity<PredictionResult> predictSingle(@RequestBody PacketData packetData) {
        if (packetData == null) {
            return ResponseEntity.badRequest().build();
        }
        PredictionResult result = detectorService.predictPacket(packetData);

        if (result.getIsAttack() && packetData.getMeta() != null && packetData.getMeta().containsKey("src_ip")) {
            activeDefenseService.recordPacket(
                    packetData.getMeta(), result.getAttackType(), result.getConfidence(),
                    result.getIsAttack(), result.getSeverity(), result.getReasons()
            );
        }

        return ResponseEntity.ok(result);
    }

    @PostMapping(value = "/scan-file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> scanFile(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No file uploaded"));
        }

        String filename = file.getOriginalFilename() != null ? file.getOriginalFilename().toLowerCase() : "";
        if (!filename.endsWith(".csv") && !filename.endsWith(".pcap") && !filename.endsWith(".pcapng")) {
            return ResponseEntity.badRequest().body(Map.of("error", "Unsupported file format. Please upload .csv or .pcap"));
        }

        try (InputStream is = file.getInputStream()) {
            List<PredictionResult> results = detectorService.predictBatchCsv(is, 500);

            int total = results.size();
            int threatCount = 0;
            Map<String, Integer> breakdown = new HashMap<>();

            for (PredictionResult r : results) {
                if (r.getIsAttack()) threatCount++;
                String atk = r.getAttackType();
                breakdown.put(atk, breakdown.getOrDefault(atk, 0) + 1);
            }

            FileScanResponse response = new FileScanResponse();
            response.setFilename(file.getOriginalFilename());
            response.setTotalAnalyzed(total);
            response.setThreatsDetected(threatCount);
            response.setSafeCount(total - threatCount);
            double pct = total > 0 ? (double) Math.round(((double) threatCount / total) * 10000.0) / 100.0 : 0.0;
            response.setThreatPercentage(pct);
            response.setBreakdown(breakdown);
            response.setSamples(results.subList(0, Math.min(50, total)));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to process file: " + e.getMessage()));
        }
    }

    @PostMapping("/simulate/start")
    public ResponseEntity<Map<String, Object>> startSimulator(@RequestBody(required = false) Map<String, Object> req) {
        String mode = req != null && req.containsKey("mode") ? (String) req.get("mode") : "mixed";
        double delay = req != null && req.containsKey("delay") ? ((Number) req.get("delay")).doubleValue() : 0.8;
        trafficSimulatorService.start(mode, delay);
        return ResponseEntity.ok(Map.of("status", "SUCCESS", "mode", mode, "delay", delay));
    }

    @PostMapping("/simulate/stop")
    public ResponseEntity<Map<String, Object>> stopSimulator() {
        trafficSimulatorService.stop();
        return ResponseEntity.ok(Map.of("status", "SUCCESS", "message", "Simulator paused."));
    }

    @PostMapping("/simulate/burst")
    public ResponseEntity<Map<String, Object>> burstSimulator(@RequestBody(required = false) Map<String, Object> req) {
        String attack = req != null && req.containsKey("attack") ? (String) req.get("attack") : "syn_flood";
        int count = req != null && req.containsKey("count") ? ((Number) req.get("count")).intValue() : 15;
        trafficSimulatorService.triggerBurst(attack, count);
        return ResponseEntity.ok(Map.of("status", "SUCCESS", "message", "Burst " + attack + " triggered with " + count + " packets."));
    }

    @GetMapping("/firewall/list")
    public ResponseEntity<FirewallListResponse> getFirewallList() {
        return ResponseEntity.ok(new FirewallListResponse(
                activeDefenseService.getActiveBlockedHosts(),
                activeDefenseService.getRecentIncidents(50)
        ));
    }

    @PostMapping("/firewall/block")
    public ResponseEntity<?> blockIp(@RequestBody Map<String, String> req) {
        String ip = req != null ? req.get("ip") : null;
        String reason = req != null ? req.getOrDefault("reason", "Manual SOC block") : "Manual SOC block";
        if (ip == null || ip.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing IP parameter"));
        }
        boolean success = activeDefenseService.blockIp(ip, reason, "Manual");
        return ResponseEntity.ok(Map.of("success", success, "ip", ip));
    }

    @PostMapping("/firewall/unblock")
    public ResponseEntity<?> unblockIp(@RequestBody Map<String, String> req) {
        String ip = req != null ? req.get("ip") : null;
        if (ip == null || ip.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing IP parameter"));
        }
        boolean success = activeDefenseService.unblockIp(ip);
        return ResponseEntity.ok(Map.of("success", success, "ip", ip));
    }

    @GetMapping("/presets")
    public ResponseEntity<?> getPresets() {
        try {
            ClassPathResource res = new ClassPathResource("static/samples/attack_samples.json");
            if (res.exists()) {
                Map<?, ?> json = objectMapper.readValue(res.getInputStream(), Map.class);
                return ResponseEntity.ok(json);
            }
        } catch (Exception ignored) {}
        return ResponseEntity.ok(Map.of());
    }

    @GetMapping("/models/metadata")
    public ResponseEntity<?> getModelsMetadata() {
        try {
            ClassPathResource res = new ClassPathResource("static/models/metadata.json");
            if (res.exists()) {
                Map<?, ?> json = objectMapper.readValue(res.getInputStream(), Map.class);
                return ResponseEntity.ok(json);
            }
        } catch (Exception ignored) {}
        return ResponseEntity.ok(Map.of());
    }

    @GetMapping("/export-logs")
    public ResponseEntity<byte[]> exportLogs() {
        List<SecurityIncident> incidents = activeDefenseService.getIncidentsForExport();
        StringBuilder sb = new StringBuilder();
        sb.append("ID,Timestamp,Time,Source IP,Destination IP,Source Port,Destination Port,Protocol,Attack Type,Confidence,Severity,Action,Blocked,Reasons\n");

        for (SecurityIncident inc : incidents) {
            sb.append(inc.getId()).append(",")
                    .append(inc.getTimestamp()).append(",")
                    .append(escapeCsv(inc.getTimeStr())).append(",")
                    .append(escapeCsv(inc.getSrcIp())).append(",")
                    .append(escapeCsv(inc.getDstIp())).append(",")
                    .append(inc.getSrcPort() != null ? inc.getSrcPort() : 0).append(",")
                    .append(inc.getDstPort() != null ? inc.getDstPort() : 0).append(",")
                    .append(escapeCsv(inc.getProtocol())).append(",")
                    .append(escapeCsv(inc.getAttackType())).append(",")
                    .append(inc.getConfidence()).append(",")
                    .append(escapeCsv(inc.getSeverity())).append(",")
                    .append(escapeCsv(inc.getAction())).append(",")
                    .append(inc.getIsBlocked()).append(",")
                    .append(escapeCsv(inc.getReasons())).append("\n");
        }

        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=cybershield_incidents_" + System.currentTimeMillis() + ".csv")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(bytes);
    }

    @PostMapping("/url/check")
    public ResponseEntity<UrlCheckResult> checkUrlPost(@RequestBody Map<String, String> req) {
        String url = req != null ? req.get("url") : "";
        return ResponseEntity.ok(urlSecurityService.analyzeUrl(url));
    }

    @GetMapping("/url/check")
    public ResponseEntity<UrlCheckResult> checkUrlGet(@RequestParam(value = "url", defaultValue = "") String url) {
        return ResponseEntity.ok(urlSecurityService.analyzeUrl(url));
    }

    private String escapeCsv(String str) {
        if (str == null) return "";
        if (str.contains(",") || str.contains("\"") || str.contains("\n")) {
            return "\"" + str.replace("\"", "\"\"") + "\"";
        }
        return str;
    }
}
