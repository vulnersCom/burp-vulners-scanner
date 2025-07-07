package burp.tasks;

import burp.Utils;
import burp.HttpClient;
import burp.models.VulnersRequest;
import burp.models.Software;
import burp.models.Vulnerability;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Set;
import java.util.function.Consumer;

public class SoftwareScanTask extends Thread {

    private HttpClient httpClient;
    private Consumer<VulnersRequest> callback;
    private VulnersRequest vulnersRequest;
    private Utils utils;

    public SoftwareScanTask(VulnersRequest vulnersRequest, HttpClient httpClient, Consumer<VulnersRequest> callback) {
        this.httpClient = httpClient;
        this.vulnersRequest = vulnersRequest;
        this.callback = callback;

        this.utils = new Utils(httpClient);
    }

    @Override
    public void run() {

        Software software = vulnersRequest.getSoftware();

        JSONObject data = httpClient.getVulnerableSoftware( new HashMap<String, String>() {{
            put("software", software.getAlias());
            put("version", software.getVersion());
            put("type", software.getMatchType());
        }});

        Set<Vulnerability> vulnerabilities = utils.getVulnerabilities(data);

        vulnersRequest.setVulnerabilities(vulnerabilities);

        callback.accept(vulnersRequest);
    }
}
