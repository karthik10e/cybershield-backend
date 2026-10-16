package com.cybershield.cybershield.service;

import com.cybershield.cybershield.dto.EnrichedPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class SseStreamingService {

    private static final Logger logger = LoggerFactory.getLogger(SseStreamingService.class);
    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    public SseEmitter createEmitter() {
        SseEmitter emitter = new SseEmitter(0L); // Infinite timeout for SOC stream
        emitters.add(emitter);

        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> emitters.remove(emitter));
        emitter.onError(e -> emitters.remove(emitter));

        return emitter;
    }

    public void broadcastPacket(EnrichedPacket packet) {
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event()
                        .name("packet")
                        .data(packet));
            } catch (IOException e) {
                emitters.remove(emitter);
                logger.debug("SSE client disconnected");
            } catch (Exception e) {
                emitters.remove(emitter);
            }
        }
    }

    public int getConnectedCount() {
        return emitters.size();
    }
}
