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
    private Map<String, Domain> domains;


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
                startStop,
                domains.get(domainName).getSoftware().get(software.getKey())
        );

        // add Information Burp issue
        if (software.getVersion() == null) {
            callbacks.addScanIssue(softwareIssue);
            return;
        }

        VulnersRequest request = new VulnersRequest(domainName, software, softwareIssue);

        new SoftwareScanTask(request, httpClient, vulnersRequest -> {

            Set<Vulnerability> vulnerabilities = vulnersRequest.getVulnerabilities();

            // update cache
            for (Vulnerability vulnerability : vulnerabilities) {
                domains.get(vulnersRequest.getDomain())
                        .getSoftware()
                        .get(vulnersRequest.getSoftware().getKey())
                        .getVulnerabilities()
                        .add(vulnerability);
            }

            // update gui component
            tabComponent.getSoftwareTable().refreshTable(domains, tabComponent.getCbxSoftwareShowVuln().isSelected());

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

            if (vulnerabilities.isEmpty()) {
                return;
            }

            // update cache
            domains.get(vulnersRequest.getDomain())
                    .getPaths()
                    .put(vulnersRequest.getPath(), vulnerabilities);

            // update gui component
            tabComponent.getPathsTable().getDefaultModel().addRow(new Object[]{
                    vulnersRequest.getDomain(),
                    vulnersRequest.getPath(),
                    Utils.getMaxScore(vulnerabilities),
                    Utils.getVulnersList(vulnerabilities)
            });

            // add Burp issue
            callbacks.addScanIssue(new PathIssue(
                    vulnersRequest.getBaseRequestResponse(),
                    helpers,
                    callbacks,
                    vulnersRequest.getPath(),
                    vulnerabilities
            ));
        }).run();
    }

    /**
     * Check out rules for matching
     */
    public void loadRules() throws IOException {

        JSONObject data = httpClient.get("rules", new HashMap<String, String>());

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
                callbacks.printError("[Vulners] Unable to compile pattern: " + v.getString("regex") + " for: " + key);
                burpExtender.printStackTrace(pse);
            }
        }
    }

}
