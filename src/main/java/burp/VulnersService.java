package burp;


import burp.gui.TabComponent;
import burp.models.Domain;
import burp.models.Software;
import burp.models.Vulnerability;
import com.codemagi.burp.MatchRule;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.google.common.util.concurrent.RateLimiter;
import org.json.JSONObject;

import javax.swing.table.DefaultTableModel;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static burp.VulnersServiceRequest.vulnersRestServiceGetRequest;

public class VulnersService {

    private BurpExtender burpExtender;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final TabComponent tabComponent;
    private Map<String, Domain> domains;

    private final RateLimiter rateLimiter;

    public VulnersService(BurpExtender burpExtender, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, Map<String, Domain> domains, TabComponent tabComponent) {
        this.burpExtender = burpExtender;
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.domains = domains;
        this.tabComponent = tabComponent;
        this.rateLimiter = RateLimiter.create(tabComponent.getTbxReqLimitValue());
    }

    /**
     * Check found software for vulnerabilities using https://vulnes.com/api/v3/burp/software/
     *
     * @param domainName
     * @param software
     * @param baseRequestResponse
     * @param startStop
     */
    void checkSoftware(final String domainName, final Software software, final IHttpRequestResponse baseRequestResponse, final List<int[]> startStop) {

        // Limiting requests rate
        // TODO make non block MQ
        rateLimiter.acquire();

        VulnersServiceRequest request = vulnersRestServiceGetRequest(callbacks)
                .pathParameter("software")
                .queryString("software", software.getAlias())
                .queryString("version", software.getVersion())
                .queryString("type", software.getMatchType());

        callbacks.printOutput("[Vulners] start check for domain " + domainName + " for software " + software.getName() + "/" + software.getVersion() + " : " + request.url());

        request.send(new VulnersRestCallback(callbacks) {

            @Override
            public void onScannerSuccess(Set<Vulnerability> vulnerabilities) {

                for (Vulnerability vulnerability : vulnerabilities) {
                    // update cache
                    domains.get(domainName)
                            .getSoftware()
                            .get(software.getKey())
                            .getVulnerabilities()
                            .add(vulnerability);
                }

                // update gui component
                tabComponent.getSoftwareTable().refreshTable(domains, tabComponent.getCbxSoftwareShowVuln().isSelected());


                // add Burp issue
                callbacks.addScanIssue(new SoftwareIssue(
                        baseRequestResponse,
                        helpers,
                        callbacks,
                        startStop,
                        domains.get(domainName).getSoftware().get(software.getKey())
                ));
            }

            @Override
            public void onFail(String error) {
                // update gui component
                tabComponent.getSoftwareTable().refreshTable(domains, tabComponent.getCbxSoftwareShowVuln().isSelected());

                callbacks.addScanIssue(new SoftwareIssue(
                        baseRequestResponse,
                        helpers,
                        callbacks,
                        startStop,
                        domains.get(domainName).getSoftware().get(software.getKey())
                ));
            }
        });
    }

    /**
     * Check found software for vulnerabilities using https://vulnes.com/api/v3/burp/path/
     *
     * @param domainName
     * @param path
     * @param baseRequestResponse
     */
    void checkURLPath(final String domainName, final String path, final IHttpRequestResponse baseRequestResponse) {
        // Limiting requests rate
        // TODO make non block MQ
        rateLimiter.acquire();

        vulnersRestServiceGetRequest(callbacks)
                .pathParameter("path")
                .queryString("path", path)
                .send(new VulnersRestCallback(callbacks) {

                    @Override
                    public void onScannerSuccess(Set<Vulnerability> vulnerabilities) {

                        // update cache
                        domains.get(domainName)
                                .getPaths()
                                .put(path, vulnerabilities);

                        // update gui component
                        tabComponent.getPathsTable().getDefaultModel().addRow(new Object[]{
                                domainName,
                                path,
                                Utils.getMaxScore(vulnerabilities),
                                Utils.getVulnersList(vulnerabilities)
                        });

                        // add Burp issue
                        callbacks.addScanIssue(new PathIssue(
                                baseRequestResponse,
                                helpers,
                                callbacks,
                                path,
                                vulnerabilities
                        ));
                    }
                });
    }

    /**
     * Check out rules for matching
     */
    public void loadRules() {
        vulnersRestServiceGetRequest(callbacks)
                .pathParameter("rules")
                .send(new VulnersRestCallback(callbacks) {
                    @Override
                    public void onSuccess(JSONObject data) {
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

                                burpExtender.getMatchRules().put(key, new HashMap<String, String>() {{
                                    put("regex", v.getString("regex"));
                                    put("alias", v.getString("alias"));
                                    put("type", v.getString("type"));
                                }});
                                // Match group 1 - is important
                                burpExtender.addMatchRule(new MatchRule(pattern, 1, key, ScanIssueSeverity.LOW, ScanIssueConfidence.CERTAIN));
                            } catch (PatternSyntaxException pse) {
                                callbacks.printError("Unable to compile pattern: " + v.getString("regex") + " for: " + key);
                                burpExtender.printStackTrace(pse);
                            }
                        }
                    }
                });
    }
}
