package com.cybershield.cybershield.dto;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.HashMap;
import java.util.Map;

public class PacketData {

    private Double duration = 0.0;

    @JsonProperty("protocol_type")
    private String protocolType = "tcp";

    private String service = "http";
    private String flag = "SF";

    @JsonProperty("src_bytes")
    private Long srcBytes = 0L;

    @JsonProperty("dst_bytes")
    private Long dstBytes = 0L;

    private Integer land = 0;

    @JsonProperty("wrong_fragment")
    private Integer wrongFragment = 0;

    private Integer urgent = 0;
    private Integer hot = 0;

    @JsonProperty("num_failed_logins")
    private Integer numFailedLogins = 0;

    @JsonProperty("logged_in")
    private Integer loggedIn = 0;

    @JsonProperty("num_compromised")
    private Integer numCompromised = 0;

    @JsonProperty("root_shell")
    private Integer rootShell = 0;

    @JsonProperty("su_attempted")
    private Integer suAttempted = 0;

    @JsonProperty("num_root")
    private Integer numRoot = 0;

    @JsonProperty("num_file_creations")
    private Integer numFileCreations = 0;

    private Integer count = 1;

    @JsonProperty("srv_count")
    private Integer srvCount = 1;

    @JsonProperty("serror_rate")
    private Double serrorRate = 0.0;

    @JsonProperty("rerror_rate")
    private Double rerrorRate = 0.0;

    @JsonProperty("same_srv_rate")
    private Double sameSrvRate = 1.0;

    @JsonProperty("diff_srv_rate")
    private Double diffSrvRate = 0.0;

    @JsonProperty("dst_host_count")
    private Integer dstHostCount = 1;

    @JsonProperty("dst_host_srv_count")
    private Integer dstHostSrvCount = 1;

    @JsonProperty("_meta")
    private Map<String, Object> meta = new HashMap<>();

    private Map<String, Object> otherFields = new HashMap<>();

    public PacketData() {}

    public Double getDuration() { return duration; }
    public void setDuration(Double duration) { this.duration = duration; }

    public String getProtocolType() { return protocolType; }
    public void setProtocolType(String protocolType) { this.protocolType = protocolType; }

    public String getService() { return service; }
    public void setService(String service) { this.service = service; }

    public String getFlag() { return flag; }
    public void setFlag(String flag) { this.flag = flag; }

    public Long getSrcBytes() { return srcBytes; }
    public void setSrcBytes(Long srcBytes) { this.srcBytes = srcBytes; }

    public Long getDstBytes() { return dstBytes; }
    public void setDstBytes(Long dstBytes) { this.dstBytes = dstBytes; }

    public Integer getLand() { return land; }
    public void setLand(Integer land) { this.land = land; }

    public Integer getWrongFragment() { return wrongFragment; }
    public void setWrongFragment(Integer wrongFragment) { this.wrongFragment = wrongFragment; }

    public Integer getUrgent() { return urgent; }
    public void setUrgent(Integer urgent) { this.urgent = urgent; }

    public Integer getHot() { return hot; }
    public void setHot(Integer hot) { this.hot = hot; }

    public Integer getNumFailedLogins() { return numFailedLogins; }
    public void setNumFailedLogins(Integer numFailedLogins) { this.numFailedLogins = numFailedLogins; }

    public Integer getLoggedIn() { return loggedIn; }
    public void setLoggedIn(Integer loggedIn) { this.loggedIn = loggedIn; }

    public Integer getNumCompromised() { return numCompromised; }
    public void setNumCompromised(Integer numCompromised) { this.numCompromised = numCompromised; }

    public Integer getRootShell() { return rootShell; }
    public void setRootShell(Integer rootShell) { this.rootShell = rootShell; }

    public Integer getSuAttempted() { return suAttempted; }
    public void setSuAttempted(Integer suAttempted) { this.suAttempted = suAttempted; }

    public Integer getNumRoot() { return numRoot; }
    public void setNumRoot(Integer numRoot) { this.numRoot = numRoot; }

    public Integer getNumFileCreations() { return numFileCreations; }
    public void setNumFileCreations(Integer numFileCreations) { this.numFileCreations = numFileCreations; }

    public Integer getCount() { return count; }
    public void setCount(Integer count) { this.count = count; }

    public Integer getSrvCount() { return srvCount; }
    public void setSrvCount(Integer srvCount) { this.srvCount = srvCount; }

    public Double getSerrorRate() { return serrorRate; }
    public void setSerrorRate(Double serrorRate) { this.serrorRate = serrorRate; }

    public Double getRerrorRate() { return rerrorRate; }
    public void setRerrorRate(Double rerrorRate) { this.rerrorRate = rerrorRate; }

    public Double getSameSrvRate() { return sameSrvRate; }
    public void setSameSrvRate(Double sameSrvRate) { this.sameSrvRate = sameSrvRate; }

    public Double getDiffSrvRate() { return diffSrvRate; }
    public void setDiffSrvRate(Double diffSrvRate) { this.diffSrvRate = diffSrvRate; }

    public Integer getDstHostCount() { return dstHostCount; }
    public void setDstHostCount(Integer dstHostCount) { this.dstHostCount = dstHostCount; }

    public Integer getDstHostSrvCount() { return dstHostSrvCount; }
    public void setDstHostSrvCount(Integer dstHostSrvCount) { this.dstHostSrvCount = dstHostSrvCount; }

    public Map<String, Object> getMeta() { return meta; }
    public void setMeta(Map<String, Object> meta) { this.meta = meta; }

    @JsonAnyGetter
    public Map<String, Object> getOtherFields() { return otherFields; }

    @JsonAnySetter
    public void setOtherField(String key, Object value) {
        this.otherFields.put(key, value);
    }
}
