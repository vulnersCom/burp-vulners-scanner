package burp;


import burp.gui.TabComponent;
import burp.models.Domain;
import burp.models.Software;
import burp.models.Vulnerability;
import com.codemagi.burp.MatchRule;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;
import com.google.common.util.concurrent.RateLimiter;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.request.HttpRequest;
import org.apache.http.HttpHost;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.json.JSONObject;

import javax.swing.table.DefaultTableModel;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class VulnersService {

    private static String BURP_API_URL = "https://vulners.com/api/v3/burp/{path}/";
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
        this.rateLimiter = RateLimiter.create(4.0);  // Count of max RPS

        Unirest.setDefaultHeader("user-agent", "vulners-burpscanner-v-1.1");
        Unirest.setAsyncHttpClient(HttpClient.createSSLClient());
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

        final HttpRequest request = Unirest.get(BURP_API_URL)
                .routeParam("path", "software")
                .queryString("software", software.getAlias())
                .queryString("version", software.getVersion())
                .queryString("type", software.getMatchType());

        callbacks.printOutput("[Vulners] start check for domain " + domainName + " for software " + software.getName() + "/" + software.getVersion() + " : " + request.getUrl());

        request.asJsonAsync(new VulnersRestCallback(callbacks) {

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
            public void onFail(JSONObject error) {
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

        Unirest.get(BURP_API_URL)
                .routeParam("path", "path")
                .queryString("path", path)
                .asJsonAsync(new VulnersRestCallback(callbacks) {

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
        Unirest.get(BURP_API_URL)
                .routeParam("path", "rules")
                .asJsonAsync(new VulnersRestCallback(callbacks) {

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
                                System.out.println("[NEW] " + pattern);

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

    public static void buildHttpClient(String host, String port) {
        try {
            if ("".equals(host) && "".equals(port)) {
                Unirest.setAsyncHttpClient(null);
            } else {
                Unirest.setAsyncHttpClient(HttpClient.createSSLClient(new HttpHost(host, Integer.valueOf(port))));
            }
        } catch (Exception e) {
            System.out.println("[Vulners] can't build HTTP client");
        }
    }
}
