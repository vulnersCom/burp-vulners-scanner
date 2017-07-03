package burp;


import burp.models.Domain;
import burp.models.Software;
import burp.models.Vulnerability;
import com.codemagi.burp.ScannerMatch;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.async.Callback;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.Map;

class SoftwareCallback implements Callback<JsonNode> {

    private static String BURP_API_URL = "https://vulners.com/api/v3/burp/{path}/";
    private final IBurpExtenderCallbacks callbacks;
    private final List<int[]> startStop;
    private final Software software;
    private final String domainName;
    private List<ScannerMatch> matches;
    private final IExtensionHelpers helpers;
    private final IHttpRequestResponse baseRequestResponse;
    private Map<String, Domain> domains;


    public SoftwareCallback(IHttpRequestResponse baseRequestResponse, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, Map<String, Domain> domains, List<int[]> startStop, Software software, String domainName, List<ScannerMatch> matches) {
        this.baseRequestResponse = baseRequestResponse;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.domains = domains;
        this.startStop = startStop;
        this.software = software;
        this.domainName = domainName;
        this.matches = matches;
    }

    public void failed(UnirestException e) {}

    public void cancelled() {}

    public void completed(HttpResponse<JsonNode> response) {
        callbacks.printOutput("[Vulners] Response for " + domainName + " " + software.getName() + "/" + software.getVersion() +  ": " + response.getBody());
        if ("ERROR".equals(response.getBody().getObject().getString("result"))) {
            try {
                callbacks.addScanIssue(new SoftwareIssue(
                        baseRequestResponse,
                        helpers,
                        callbacks,
                        startStop,
                        domains.get(domainName).getSoftware().get(software.getKey())
                ));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return;
        }

        JSONArray bulletins = response.getBody().getObject()
                .getJSONObject("data")
                .getJSONArray("search");

        for (Object bulletin : bulletins) {
            JSONObject jBulletin = ((JSONObject) bulletin).getJSONObject("_source");

            domains.get(domainName)
                    .getSoftware()
                    .get(software.getKey())
                    .getVulnerabilities()
                    .add(new Vulnerability(
                            jBulletin.getString("id"),
                            jBulletin.getString("title"),
                            jBulletin.getString("description"),
                            jBulletin.getString("type"),
                            jBulletin.getJSONObject("cvss").getDouble("score")
                    ));
        }

        callbacks.addScanIssue(new SoftwareIssue(
                baseRequestResponse,
                helpers,
                callbacks,
                startStop,
                domains.get(domainName).getSoftware().get(software.getKey())
        ));

    }

}
