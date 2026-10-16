package com.cybershield.cybershield.dto;

import com.cybershield.cybershield.model.QuarantinedHost;
import com.cybershield.cybershield.model.SecurityIncident;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class FirewallListResponse {

    @JsonProperty("blocked_ips")
    private List<QuarantinedHost> blockedIps;

    private List<SecurityIncident> incidents;

    public FirewallListResponse() {}

    public FirewallListResponse(List<QuarantinedHost> blockedIps, List<SecurityIncident> incidents) {
        this.blockedIps = blockedIps;
        this.incidents = incidents;
    }

    public List<QuarantinedHost> getBlockedIps() { return blockedIps; }
    public void setBlockedIps(List<QuarantinedHost> blockedIps) { this.blockedIps = blockedIps; }

    public List<SecurityIncident> getIncidents() { return incidents; }
    public void setIncidents(List<SecurityIncident> incidents) { this.incidents = incidents; }
}
