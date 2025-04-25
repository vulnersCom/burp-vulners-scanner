package burp.tasks;

import burp.HttpClient;
import burp.Utils;
import burp.models.Vulnerability;
import burp.models.VulnersRequest;
import com.google.common.collect.Lists;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

public class PathScanTask extends Thread {

    private HttpClient httpClient;
    private Consumer<VulnersRequest> callback;
    private VulnersRequest vulnersRequest;
    private Utils utils;

    public PathScanTask(VulnersRequest vulnersRequest, HttpClient httpClient, Consumer<VulnersRequest> callback) {
        this.httpClient = httpClient;
        this.vulnersRequest = vulnersRequest;
        this.callback = callback;

        this.utils = new Utils(httpClient);
    }

    @Override
    public void run() {

//        JSONObject data = httpClient.post("path", new HashMap<String, String>() {{
//            put("path", vulnersRequest.getPath());
//        }});
        List<String> paths = Lists.newArrayList();
//        paths.add(vulnersRequest.getPath());
        vulnersRequest.getDomain();

        paths.add("/wp-content/cache/");

        JSONObject data = httpClient.getVulnerablePathsV4(paths);


        Set<Vulnerability> vulnerabilities = utils.getPathVulnerabilities(data);

        vulnersRequest.setVulnerabilities(vulnerabilities);

        callback.accept(vulnersRequest);
    }
}
