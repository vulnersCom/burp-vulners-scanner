package burp.models;

import burp.IHttpRequestResponse;
import burp.SoftwareIssue;

import java.util.Set;

public class VulnersRequest {

    private String domainName;
    private String path;
    private Software software;
    private SoftwareIssue softwareIssue;
    private IHttpRequestResponse baseRequestResponse;
    private Set<Vulnerability> vulnerabilities;

    public VulnersRequest(String domainName, Software software, SoftwareIssue softwareIssue) {
        this.software = software;
        this.domainName = domainName;
        this.softwareIssue = softwareIssue;
    }

    public VulnersRequest(String domainName, String path, IHttpRequestResponse baseRequestResponse) {
        this.domainName = domainName;
        this.path = path;
        this.baseRequestResponse = baseRequestResponse;
    }

    public IHttpRequestResponse getBaseRequestResponse() {
        return baseRequestResponse;
    }

    public SoftwareIssue getSoftwareIssue() {
        return softwareIssue;
    }

    public String getPath() {
        return path;
    }

    public String getDomain() {
        return domainName;
    }

    public Software getSoftware() {
        return software;
    }

    public Set<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(Set<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
}
