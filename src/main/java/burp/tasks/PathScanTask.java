package burp.tasks;

import burp.HttpClient;
import burp.Utils;
import burp.models.Vulnerability;
import burp.models.VulnersRequest;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Set;
import java.util.function.Consumer;

public class PathScanTask extends Thread {

    private HttpClient httpClient;
    private Consumer<VulnersRequest> callback;
    private VulnersRequest vulnersRequest;

    public PathScanTask(VulnersRequest vulnersRequest, HttpClient httpClient, Consumer<VulnersRequest> callback) {
        this.httpClient = httpClient;
        this.vulnersRequest = vulnersRequest;
        this.callback = callback;
    }

    @Override
    public void run() {

        JSONObject data = httpClient.get("path", new HashMap<String, String>() {{
            put("path", vulnersRequest.getPath());
        }});

        Set<Vulnerability> vulnerabilities = Utils.getVulnerabilities(data);

        vulnersRequest.setVulnerabilities(vulnerabilities);

        callback.accept(vulnersRequest);
    }
}
