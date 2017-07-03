package burp;


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
    private Map<String, Domain> domains;

    VulnersService(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, Map<String, Domain> domains) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.domains = domains;
    }


    void checkSoftware(final String domainName, final Software software, final IHttpRequestResponse baseRequestResponse, final List<int[]> startStop, final List<ScannerMatch> matches) {

        final HttpRequest request = Unirest.get(BURP_API_URL)
                .routeParam("path", "software")
                .queryString("software", software.getName())
                .queryString("version", software.getVersion());

        callbacks.printOutput("[Vulners] start check for domain " + domainName + " for software " + software.getName() + "/" + software.getVersion() + " : " + request.getUrl());

        request.asJsonAsync(new SoftwareCallback(
                baseRequestResponse,
                helpers,
                callbacks,
                domains,
                startStop,
                software,
                domainName,
                matches
        ));
    }

    void checkURLPath(String path) {
        Unirest.get(BURP_API_URL)
                .routeParam("path", "path")
                .queryString("path", path)
                .asJsonAsync();
    }
}
