package burp;

import burp.models.PathVulnerability;
import burp.models.Vulnerability;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.google.common.base.Function;
import com.google.common.collect.Collections2;
import com.google.common.collect.Ordering;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.Set;

public class PathIssue implements IScanIssue {

    private final IHttpRequestResponse baseRequestResponse;
    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;

    private final String path;
    private final Set<Vulnerability> vulnerabilities;

    PathIssue(IHttpRequestResponse baseRequestResponse, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, String path, Set<Vulnerability> vulnerabilities) {
        this.baseRequestResponse = baseRequestResponse;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.path = path;
        this.vulnerabilities = vulnerabilities;
    }

    @Override
    public String getIssueName() {
        return "[Vulners] possible vulnerable path found";
    }

    @Override
    public String getIssueDetail() {
        String template = "! All found vulnerabilities have to be checked " +
                "The following vulnerabilities for path <b>%s</b> found: <br/>";
        String potentialString = "The following potential paths have been identified as part of this vulnerability <br/>";
        String itemTemplate = "<li> %s <br/> %s <br/><b>Param</b>: %s<br/><b>In</b>: %s<br/>";
        String potentialItemTemplate = "<li> <b>Path</b>: %s <br/><b>Param</b>: %s<br/><b>In</b>: %s<br/>";

        StringBuilder string = new StringBuilder();
        string.append(String.format(template, path));

        for (final Vulnerability v: vulnerabilities) {
            if(!v.getClass().equals(PathVulnerability.class)){
                callbacks.printError("[VULNERS] PATH Issue Vulnerabilty not PathVulnerabilty but " + v.getClass().toString());
                throw new RuntimeException("[VULNERS] PATH Issue Vulnerabilty not PathVulnerabilty");
            }
            if(((PathVulnerability) v).isOriginal()) {
                string.append(String.format(itemTemplate,
                        v.getItemLink(),
                        v.getItemDescription(),
                        ((PathVulnerability) v).getParameter(),
                        ((PathVulnerability) v).getPosition()
                ));
            }
            if(!((PathVulnerability) v).getPotentials().isEmpty()){
                // Need to add a list of all the potentials
                string.append("</br>");
                string.append(potentialString);
                string.append("<ul>");
                ((PathVulnerability) v).getPotentials().forEach(p ->
                        string.append(String.format(potentialItemTemplate,
                            p.getUrl(),
                            p.getParameter(),
                            p.getPosition()
                                )
                        )
                );
                string.append("</ul>");
            }
        }

        return string.toString();
    }

    @Override
    public String getSeverity() {
        Collection<Double> scores = Collections2.transform(
                vulnerabilities, new Function<Vulnerability, Double>() {
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
        return new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, null)};
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
