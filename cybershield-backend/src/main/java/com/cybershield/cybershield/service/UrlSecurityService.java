package com.cybershield.cybershield.service;

import com.cybershield.cybershield.dto.UrlCheckResult;
import com.cybershield.cybershield.model.UrlScanResult;
import com.cybershield.cybershield.repository.UrlScanResultRepository;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class UrlSecurityService {

    private final UrlScanResultRepository urlScanResultRepository;

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            ".xyz", ".top", ".cc", ".buzz", ".fit", ".tk", ".ml", ".ga",
            ".cf", ".gq", ".work", ".click", ".link", ".rest", ".ru", ".cn"
    );

    private static final List<String> PHISHING_KEYWORDS = List.of(
            "login", "signin", "verify", "secure", "banking", "account",
            "update", "wallet", "password", "credential", "auth", "paypal",
            "crypto", "invoice", "suspended", "security-alert"
    );

    private static final Pattern IP_PATTERN = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    public UrlSecurityService(UrlScanResultRepository urlScanResultRepository) {
        this.urlScanResultRepository = urlScanResultRepository;
    }

    public UrlCheckResult analyzeUrl(String inputUrl) {
        UrlCheckResult result = new UrlCheckResult();
        if (inputUrl == null || inputUrl.isBlank()) {
            result.setUrl("");
            result.setRiskScore(100);
            result.setRiskLevel("DANGEROUS");
            result.setFlags(List.of("Empty URL provided"));
            result.setRecommendations(List.of("Enter a valid URL to inspect."));
            return result;
        }

        String cleanedUrl = inputUrl.trim();
        if (!cleanedUrl.startsWith("http://") && !cleanedUrl.startsWith("https://")) {
            cleanedUrl = "https://" + cleanedUrl;
        }
        result.setUrl(cleanedUrl);

        List<String> flags = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();
        int riskScore = 0;

        try {
            URI uri = new URI(cleanedUrl);
            String host = uri.getHost();
            if (host == null) {
                throw new IllegalArgumentException("Invalid domain structure");
            }
            result.setDomain(host);

            boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
            result.setIsHttps(isHttps);
            if (!isHttps) {
                riskScore += 25;
                flags.add("Unencrypted HTTP Protocol: Data transmitted in cleartext without SSL/TLS certificate");
                recommendations.add("Avoid entering sensitive personal credentials on unencrypted HTTP connections.");
            }

            boolean isIp = IP_PATTERN.matcher(host).matches();
            result.setIsIpAddress(isIp);
            if (isIp) {
                riskScore += 40;
                flags.add("Raw IP Address as Hostname: Common evasive tactic used by malicious phishing hosts");
                recommendations.add("Do not interact with websites hosted directly on raw IP addresses instead of registered domain names.");
            }

            String lowerHost = host.toLowerCase();
            boolean suspiciousTld = SUSPICIOUS_TLDS.stream().anyMatch(lowerHost::endsWith);
            result.setIsSuspiciousTld(suspiciousTld);
            if (suspiciousTld) {
                riskScore += 30;
                flags.add("High-Risk Top-Level Domain (TLD) associated with spam and phishing campaigns");
                recommendations.add("Verify the legitimacy of domains ending in high-abuse TLDs before proceeding.");
            }

            // Check for excessive subdomains (e.g. paypal.com.security-check.xyz)
            String[] parts = host.split("\\.");
            if (parts.length > 3) {
                riskScore += 20;
                flags.add("Excessive Domain Sublevels (" + parts.length + " levels): Possible brand impersonation");
                recommendations.add("Examine the root domain name carefully to ensure it is not spoofing a known brand.");
            }

            // Keyword analysis in URL
            String fullPathLower = cleanedUrl.toLowerCase();
            int matchedKeywords = 0;
            for (String kw : PHISHING_KEYWORDS) {
                if (fullPathLower.contains(kw)) {
                    matchedKeywords++;
                }
            }
            if (matchedKeywords >= 2) {
                riskScore += 25;
                flags.add("Multiple high-risk security/credential keywords detected in URL path");
                recommendations.add("Ensure you were not redirected here via an unsolicited message or email link.");
            } else if (matchedKeywords == 1 && (!isHttps || suspiciousTld || isIp)) {
                riskScore += 15;
                flags.add("Sensitive authentication keyword combined with high-risk domain attributes");
            }

            // Hyphen count in hostname
            long hyphenCount = host.chars().filter(ch -> ch == '-').count();
            if (hyphenCount >= 3) {
                riskScore += 15;
                flags.add("Suspicious hyphenated domain name pattern");
            }

        } catch (Exception e) {
            riskScore = 80;
            flags.add("Malformed or unparseable URL syntax: " + e.getMessage());
            recommendations.add("Please ensure the URL conforms to RFC standard web address format.");
        }

        riskScore = Math.min(100, riskScore);
        result.setRiskScore(riskScore);

        if (riskScore >= 60) {
            result.setRiskLevel("DANGEROUS");
            recommendations.add("CRITICAL: High probability of phishing or scam payload. Access is strongly discouraged.");
        } else if (riskScore >= 25) {
            result.setRiskLevel("SUSPICIOUS");
            recommendations.add("Proceed with caution. Verify the sender and domain reputation.");
        } else {
            result.setRiskLevel("SAFE");
            flags.add("Standard URL structure with valid HTTPS encryption verified");
            recommendations.add("No immediate phishing or malformed URL patterns detected.");
        }

        result.setFlags(flags);
        result.setRecommendations(recommendations);

        // Save scan result to MySQL
        try {
            UrlScanResult entity = new UrlScanResult(
                    result.getUrl(),
                    result.getDomain(),
                    result.getRiskScore(),
                    result.getRiskLevel(),
                    result.getIsHttps(),
                    result.getIsIpAddress(),
                    result.getIsSuspiciousTld(),
                    String.join("; ", flags)
            );
            urlScanResultRepository.save(entity);
        } catch (Exception ignored) {}

        return result;
    }
}
