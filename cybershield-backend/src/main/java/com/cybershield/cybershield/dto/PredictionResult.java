package com.cybershield.cybershield.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

public class PredictionResult {

    @JsonProperty("attack_type")
    private String attackType;

    @JsonProperty("is_attack")
    private Boolean isAttack;

    private Double confidence;
    private String severity;

    @JsonProperty("anomaly_score")
    private Double anomalyScore;

    @JsonProperty("is_zero_day")
    private Boolean isZeroDay;

    private List<String> reasons;
    private Map<String, Object> features;
    private Map<String, Object> metadata;

    public PredictionResult() {}

    public PredictionResult(String attackType, Boolean isAttack, Double confidence,
                            String severity, Double anomalyScore, Boolean isZeroDay,
                            List<String> reasons, Map<String, Object> features,
                            Map<String, Object> metadata) {
        this.attackType = attackType;
        this.isAttack = isAttack;
        this.confidence = confidence;
        this.severity = severity;
        this.anomalyScore = anomalyScore;
        this.isZeroDay = isZeroDay;
        this.reasons = reasons;
        this.features = features;
        this.metadata = metadata;
    }

    public String getAttackType() { return attackType; }
    public void setAttackType(String attackType) { this.attackType = attackType; }

    public Boolean getIsAttack() { return isAttack; }
    public void setIsAttack(Boolean isAttack) { this.isAttack = isAttack; }

    public Double getConfidence() { return confidence; }
    public void setConfidence(Double confidence) { this.confidence = confidence; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public Double getAnomalyScore() { return anomalyScore; }
    public void setAnomalyScore(Double anomalyScore) { this.anomalyScore = anomalyScore; }

    public Boolean getIsZeroDay() { return isZeroDay; }
    public void setIsZeroDay(Boolean isZeroDay) { this.isZeroDay = isZeroDay; }

    public List<String> getReasons() { return reasons; }
    public void setReasons(List<String> reasons) { this.reasons = reasons; }

    public Map<String, Object> getFeatures() { return features; }
    public void setFeatures(Map<String, Object> features) { this.features = features; }

    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
}
