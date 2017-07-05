package burp;


import burp.gui.TabComponent;
import burp.models.Domain;
import burp.models.Software;
import burp.models.Vulnerability;
import com.codemagi.burp.ScannerMatch;
import com.mashape.unirest.http.*;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.async.Callback;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.mashape.unirest.request.HttpRequest;
import com.mashape.unirest.request.body.MultipartBody;
import org.apache.http.HttpHost;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.util.*;

class VulnersService {

    private static String BURP_API_URL = "https://vulners.com/api/v3/burp/{path}/";
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final TabComponent tabComponent;
    private Map<String, Domain> domains;

    VulnersService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, Map<String, Domain> domains, TabComponent tabComponent) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.domains = domains;
        this.tabComponent = tabComponent;
    }


    /**
     * Check found software for vulnerabilities using https://vulnes.com/api/v3/burp/software/
     *
     * @param domainName
     * @param software
     * @param baseRequestResponse
     * @param startStop
     * @param matches
     */
    void checkSoftware(final String domainName, final Software software, final IHttpRequestResponse baseRequestResponse, final List<int[]> startStop, final List<ScannerMatch> matches) {

        final HttpRequest request = Unirest.get(BURP_API_URL)
                .routeParam("path", "software")
                .queryString("software", software.getName())
                .queryString("version", software.getVersion());

        callbacks.printOutput("[Vulners] start check for domain " + domainName + " for software " + software.getName() + "/" + software.getVersion() + " : " + request.getUrl());

        request.asJsonAsync(new VulnersRestCallback(callbacks) {

            @Override
            public void onSuccess(Set<Vulnerability> vulnerabilities) {

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
        Unirest.get(BURP_API_URL)
                .routeParam("path", "path")
                .queryString("path", path)
                .asJsonAsync(new VulnersRestCallback(callbacks) {

                    @Override
                    public void onSuccess(Set<Vulnerability> vulnerabilities) {

                        // update cache
                        domains.get(domainName)
                                .getPaths()
                                .put(path, vulnerabilities);

                        // update gui component
                        tabComponent.getPathsTable().getDefaultModel().addRow(new Object[]{
                                domainName,
                                path,
                                0,
                                ""
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
}
