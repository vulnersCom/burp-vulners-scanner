package burp;

import burp.models.Software;
import burp.models.Vulnerability;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.google.common.base.Function;
import com.google.common.collect.Collections2;
import com.google.common.collect.Ordering;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.List;

public class SoftwareIssue implements IScanIssue {

    private final IHttpRequestResponse baseRequestResponse;
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final List<int[]> startStop;

    private final BurpExtender burpExtender;

    private Software software;

    SoftwareIssue(IHttpRequestResponse baseRequestResponse, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, BurpExtender burpExtender, List<int[]> startStop, Software software) {
        this.baseRequestResponse = baseRequestResponse;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.startStop = startStop;
        this.burpExtender = burpExtender;

        this.software = software;
    }

    @Override
    public String getIssueName() {
        return hasVulnerabilities() ?
                "[Vulners] Vulnerable Software detected" :
                "[Vulners] Software detected";
    }

    @Override
    public String getIssueDetail() {
        return hasVulnerabilities() ? getVulnerableIssue() : getClearIssue();
    }

    private String getVulnerableIssue() {
        String template = "The following vulnerabilities for software <b>%s - %s</b> found: <br/>";
        String itemTemplate = "<li> %s - %s - %s %s <br/> %s <br/> %s <br/>";

        StringBuilder string = new StringBuilder();
        string.append(String.format(template, software.getName(), software.getVersion()));


        for (final Vulnerability v: software.getVulnerabilities()) {
            string.append(String.format(itemTemplate,
                    v.getItemLink(),
                    v.getItemCvssScore(),
                    v.getTitle(),
                    v.getHasExploit() ? "<b color=\"red\">Has Exploits</b>" : "",
                    v.getItemDescription(),
                    getExploits(v)
            ));
        }


        return string.toString();
    }

    private String getClearIssue() {
        String template = "The following software was detected <b>%s - %s</b>\n" +
                "No vulnerabilities found for current version.";

        return String.format(template, software.getName(), software.getVersion());
    }

    @Override
    public String getSeverity() {
        if (hasVulnerabilities()) {
            Collection<Double> scores = Collections2.transform(
                    software.getVulnerabilities(), new Function<Vulnerability, Double>() {
                        @Override
                        public Double apply(Vulnerability vulnerability) {
                            return vulnerability.getCvssScore();
                        }
                    }
            );
            Double maxValue = Ordering.natural().max(scores);

            if (maxValue > 7) {
                return ScanIssueSeverity.HIGH.getName();
            } else if (maxValue > 4) {
                return ScanIssueSeverity.MEDIUM.getName();
            }
            return ScanIssueSeverity.LOW.getName();
        }

        return ScanIssueSeverity.INFO.getName();
    }

    @Override
    public String getConfidence() {
        return ScanIssueConfidence.FIRM.getName();
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

    public void setSoftware(Software software) {
        this.software = software;
    }

    private boolean hasVulnerabilities() {
        return !software.getVulnerabilities().isEmpty();
    }

    private String getExploits(Vulnerability vulnerability) {
        StringBuilder string = new StringBuilder();

        if (burpExtender.isPremiumSubscription() && vulnerability.getHasExploit()) {
            string.append("Exploits:<br/><ul>");
            for (String[] v: vulnerability.getExploits()) {
                string.append(String.format("<li><a href=\"https://vulners.com/%s/%s\" target=\"_blank\">%s</a></li>", v[0], v[1], v[1]));
            }
            string.append("</ul>");
        }
        return string.toString();
    }

}
