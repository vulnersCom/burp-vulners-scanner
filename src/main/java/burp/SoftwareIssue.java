package burp;

import burp.models.Software;
import burp.models.Vulnerability;
import com.codemagi.burp.ScanIssue;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.codemagi.burp.ScannerMatch;

import java.net.URL;
import java.util.List;

public class SoftwareIssue implements IScanIssue {

    private final IHttpRequestResponse baseRequestResponse;
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final List<int[]> startStop;
    private final Software software;

    SoftwareIssue(IHttpRequestResponse baseRequestResponse, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<int[]> startStop, Software software) {
        this.baseRequestResponse = baseRequestResponse;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.startStop = startStop;

        this.software = software;
    }

    @Override
    public String getIssueName() {
        if (software.getVulnerabilities().size() > 0) {
            return "[Vulners] Vulnerable Software detected";
        }

        return "[Vulners] Software detected";
    }

    @Override
    public String getIssueDetail() {
        StringBuilder description = new StringBuilder(software.getKey().length() * 256);
        description.append("The following vulnerabilities for software " + software.getName() + " - " + software.getVersion() + " found:<br><br>");

        for (Vulnerability vulnerability : software.getVulnerabilities()) {
            description.append("<li>");
            description.append(vulnerability.getId()).append(": ").append(vulnerability.getDescription());
        }

        return description.toString();
    }

    @Override
    public String getSeverity() {
        if (software.getVulnerabilities().size() > 0) {
            return ScanIssueSeverity.HIGH.getName();
        }

        return ScanIssueSeverity.MEDIUM.getName();
    }

    @Override
    public String getConfidence() {
        ScanIssueConfidence output = ScanIssueConfidence.FIRM;

        return output.getName();
    }

    @Override
    public URL getUrl() {
        return helpers.analyzeRequest(baseRequestResponse).getUrl();
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, startStop)};
    }

    @Override
    public IHttpService getHttpService() {
        return baseRequestResponse.getHttpService();
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }
}
