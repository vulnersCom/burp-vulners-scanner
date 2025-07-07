package burp;


import burp.gui.TabComponent;
import burp.models.Domain;
import burp.models.Software;
import burp.models.Vulnerability;
import burp.models.VulnersRequest;
import burp.tasks.PathScanTask;
import burp.tasks.SoftwareScanTask;
import com.codemagi.burp.MatchRule;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;


public class VulnersService {

    private BurpExtender burpExtender;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final TabComponent tabComponent;
    private final Map<String, Domain> domains;


    private final HttpClient httpClient;

    VulnersService(BurpExtender burpExtender, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, Map<String, Domain> domains, TabComponent tabComponent) {
        this.burpExtender = burpExtender;
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.domains = domains;
        this.tabComponent = tabComponent;

        this.httpClient = new HttpClient(callbacks, helpers, burpExtender);
    }

    /**
     * Check found software for vulnerabilities using https://vulnes.com/api/v3/burp/software/
     */
    void checkSoftware(final String domainName, final Software software, final IHttpRequestResponse baseRequestResponse, final List<int[]> startStop) {

        SoftwareIssue softwareIssue = new SoftwareIssue(
                baseRequestResponse,
                helpers,
                callbacks,
                burpExtender,
                startStop,
                domains.get(domainName).getSoftware().get(software.getKey())
        );

        // add Information Burp issue
        if (software.getVersion() == null) {
            callbacks.addScanIssue(softwareIssue);
            return;
        }

        String path = helpers.analyzeRequest(baseRequestResponse).getUrl().getPath();

        VulnersRequest request = new VulnersRequest(domainName, software, softwareIssue, path);

        new SoftwareScanTask(request, httpClient, vulnersRequest -> {

            Set<Vulnerability> vulnerabilities = vulnersRequest.getVulnerabilities();

            domains.get(vulnersRequest.getDomain())
                    .addSoftwareVulns(vulnersRequest.getSoftware().getKey(), vulnersRequest.getPath(), vulnerabilities);

            // add Vulnerability Burp issue
            vulnersRequest.getSoftwareIssue().setSoftware(
                    domains.get(vulnersRequest.getDomain())
                            .getSoftware()
                            .get(vulnersRequest.getSoftware().getKey())
            );
            callbacks.addScanIssue(vulnersRequest.getSoftwareIssue());
        }).run();
    }

    /**
     * Check found software for vulnerabilities using https://vulnes.com/api/v3/burp/path/
     */
    void checkURLPath(final String domainName, final String path, final IHttpRequestResponse baseRequestResponse) {
        VulnersRequest request = new VulnersRequest(domainName, path, baseRequestResponse);

        new PathScanTask(request, httpClient, vulnersRequest -> {
            Set<Vulnerability> vulnerabilities = vulnersRequest.getVulnerabilities();

            // in fact here we have PathVulnerabilities and need to add multiple issues

            if (vulnerabilities.isEmpty()) {
                return;
            }

            // update cache
            domains.get(vulnersRequest.getDomain()).addPathVulns(path, vulnerabilities);

            // add Burp issue
            callbacks.addScanIssue(new PathIssue(
                    vulnersRequest.getBaseRequestResponse(),
                    helpers,
                    callbacks,
                    burpExtender,
                    vulnersRequest.getPath(),
                    vulnerabilities
            ));
        }).run();
    }

    /**
     * Check out rules for matching
     */
    public void loadRules() throws IOException {

        JSONObject data = httpClient.getRules();

        JSONObject rules = data.getJSONObject("rules");
        Iterator<String> ruleKeys = rules.keys();

        DefaultTableModel ruleModel = tabComponent.getRulesTable().getDefaultModel();
        ruleModel.setRowCount(0); //reset table
        while (ruleKeys.hasNext()) {
            String key = ruleKeys.next();
            final JSONObject v = rules.getJSONObject(key);

            ruleModel.addRow(new Object[]{key, v.getString("regex"), v.getString("alias"), v.getString("type")});

            try {
                Pattern pattern = Pattern.compile(v.getString("regex"));
                System.out.println("[NEW] " + pattern);

                burpExtender.getMatchRules().put(key, new HashMap<String, String>() {{
                    put("regex", v.getString("regex"));
                    put("alias", v.getString("alias"));
                    put("type", v.getString("type"));
                }});

                // Match group 1 - is important
                burpExtender.addMatchRule(new MatchRule(pattern, 1, key, ScanIssueSeverity.LOW, ScanIssueConfidence.CERTAIN));
            } catch (PatternSyntaxException pse) {
                burpExtender.printError("[VULNERS] Unable to compile pattern: " + v.getString("regex") + " for: " + key);
                burpExtender.printStackTrace(pse);
            }
        }
    }

    public String isPremiumSubscription(){
        JSONObject licensesData = httpClient.getLicenses();

        if(licensesData.get("licenseList").getClass().equals(JSONArray.class)) {
            for (Object obj : licensesData.getJSONArray("licenseList")){
                if(!((JSONObject)obj).optString("type","").equals("free")){
                    // If there is at least one non-free license
                    return "true";
                }
            }
        }

        return "false";
    }

    public Map<String, Domain> getDomains() {
        return domains;
    }


}
