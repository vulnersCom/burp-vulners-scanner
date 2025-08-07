package burp;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class HttpClient {

    private static final String VULNERS_BURP_VERSION = "1.4";
    private static final String VULNERS_API_HOST = "vulners.com";
    private static final String VULNERS_API_GET_RULES_PATH = "/api/v3/burp/rules/";
    private static final String VULNERS_API_GET_LICENSES = "/api/v3/useraction/licenseids";

    private static final String VULNERS_API_PATH = "/api/v4";
    private static final String VULNERS_API_GET_WEB_VULNS = VULNERS_API_PATH + "/search/web-vulns/";
    private static final String VULNERS_API_SOFTWARE_AUDIT_PATH = VULNERS_API_PATH + "/audit/software/";

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final BurpExtender burpExtender;

    HttpClient(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    public JSONObject getLicenses() {

        if (burpExtender.getApiKey() == null) {
            burpExtender.printError("[VULNERS] GetLicenses There must be an API key.");
            return new JSONObject();
        }

        List<String> headers = new ArrayList<>();
        headers.add("GET " + VULNERS_API_GET_LICENSES + " HTTP/1.1");
        headers.add("Host: " + VULNERS_API_HOST);
        headers.add("User-Agent: vulners-burpscanner-v-" + VULNERS_BURP_VERSION );
        headers.add("X-Api-Key: " + burpExtender.getApiKey());
        headers.add("Content-type: application/json");

        JSONObject jsonBody = new JSONObject();

        byte[] request = helpers.buildHttpMessage(headers, helpers.stringToBytes(jsonBody.toString()));
        byte[] response = callbacks.makeHttpRequest(VULNERS_API_HOST, 443, true, request);

        return parseResponse(response);
    }

    public JSONObject getVulnerablePathsV4(List<String> paths) {
        if (burpExtender.getApiKey() == null) {
            burpExtender.printError("[VULNERS] getVulnerablePathsV4 There must be an API key.");
            return new JSONObject();
        }

        List<String> headers = new ArrayList<>();
        headers.add("POST " + VULNERS_API_GET_WEB_VULNS + " HTTP/1.1");
        headers.add("Host: " + VULNERS_API_HOST);
        headers.add("User-Agent: vulners-burpscanner-v-" + VULNERS_BURP_VERSION );
        headers.add("Content-type: application/json");

        JSONObject jsonBody = new JSONObject();

        jsonBody.put("paths", paths);
        jsonBody = jsonBody.put("apiKey", burpExtender.getApiKey());

        byte[] request = helpers.buildHttpMessage(headers, helpers.stringToBytes(jsonBody.toString()));
        byte[] response = callbacks.makeHttpRequest(VULNERS_API_HOST, 443, true, request);

        return parseResponseV4(response);
    }

    public JSONObject getRules() {
        List<String> headers = new ArrayList<>();
        headers.add("GET " + VULNERS_API_GET_RULES_PATH + " HTTP/1.1");
        headers.add("Host: " + VULNERS_API_HOST);
        headers.add("User-Agent: vulners-burpscanner-v-" + VULNERS_BURP_VERSION );
        headers.add("Content-type: application/json");

        JSONObject jsonBody = new JSONObject();

        byte[] request = helpers.buildHttpMessage(headers, helpers.stringToBytes(jsonBody.toString()));
        byte[] response = callbacks.makeHttpRequest(VULNERS_API_HOST, 443, true, request);
        return parseResponse(response);
    }

    public JSONObject getVulnerableSoftware(Map<String, String> params) {
        List<String> headers = new ArrayList<>();
        headers.add("POST " + VULNERS_API_SOFTWARE_AUDIT_PATH + " HTTP/1.1");
        headers.add("Host: " + VULNERS_API_HOST);
        headers.add("User-Agent: vulners-burpscanner-v-" + VULNERS_BURP_VERSION);
        headers.add("Content-type: application/json");

        JSONObject jsonBody = new JSONObject();

        if (burpExtender.getApiKey() == null) {
            burpExtender.printError("[VULNERS] getVulnerableSoftware There must be an API key.");
            return new JSONObject();
        }

        JSONArray fields = new JSONArray("[\n" +
                "\"title\"," +
                "\"type\"," +
                "\"webApplicability\"," +
                "\"description\"," +
                "\"enchantments\"," +
                "\"metrics\"]"
        );
        jsonBody = jsonBody.put("fields", fields);

        JSONObject softwareDict = new JSONObject();
        String[] software;
        switch (params.get("type")){
            case "cpe":
                software = params.get("software").split(":");
                softwareDict.put("part", software[1].substring(1));
                softwareDict.put("vendor", software[2]);
                softwareDict.put("product", software[3]);
                break;
            case "software":
                softwareDict.put("product", params.get("software"));
                break;
            case "cpe3":
                // cpe:2.3:a:ivanti:connect_secure:*:*
                software = params.get("software").split(":");
                softwareDict.put("part", software[2]);
                softwareDict.put("vendor", software[3]);
                softwareDict.put("product", software[4]);
                break;
            default:
                break;
        }

        softwareDict.put("version", params.get("version"));

        List<JSONObject> softwareList = new ArrayList<>();
        softwareList.add(softwareDict);

        jsonBody.put("software", softwareList);
        jsonBody = jsonBody.put("apiKey", burpExtender.getApiKey());

        byte[] request = helpers.buildHttpMessage(headers, helpers.stringToBytes(jsonBody.toString()));
        byte[] response = callbacks.makeHttpRequest(VULNERS_API_HOST, 443, true, request);
        return parseResponseV4(response);
    }

    private JSONObject parseResponse(byte[] response) {
        String responseString = helpers.bytesToString(response);
        IResponseInfo iResponseInfo = helpers.analyzeResponse(response);
        String jsonString = responseString.substring(iResponseInfo.getBodyOffset());

        JSONObject object = new JSONObject(jsonString);

        try {
            if (object.getString("result").equals("OK")) {
                return object.getJSONObject("data");
            } else {
                burpExtender.printOutput("[VULNERS] not OK");
                burpExtender.printOutput(jsonString);
                return object;
            }
        } catch (Exception e) {
            burpExtender.printError("[VULNERS]");
            burpExtender.printError(jsonString);
            return object;
        }
    }

    private JSONObject parseResponseV4(byte[] response) {
        String responseString = helpers.bytesToString(response);
        IResponseInfo iResponseInfo = helpers.analyzeResponse(response);
        String jsonString = responseString.substring(iResponseInfo.getBodyOffset());

        JSONObject object = new JSONObject(jsonString);

        try {
            if (iResponseInfo.getStatusCode() != 200) {
                burpExtender.printOutput("[VULNERS] V4 not OK");
                burpExtender.printOutput(jsonString);
            } else if (object.get("result").getClass().equals(String.class)) {
                // Something went wrong, and error should be in the .data.error
                String errorDesc = object.getJSONObject("data").getString("error");
                burpExtender.printError("[VULNERS] Error occured while sending http request to vulners: " + errorDesc);
            }
            return object;
        } catch (Exception e) {
            burpExtender.printError("[ERROR] V4");
            burpExtender.printError(jsonString);
            return object;
        }
    }

}
