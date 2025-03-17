package burp;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class HttpClient {

    private static final String VULNERS_BURP_VERSION = "1.4";
    private static final String VULNERS_API_HOST = "vulners.com";
    private static final String VULNERS_API_PATH = "/api/v3/burp/";

    private static final String VULNERS_API_V4_PATH = "/api/v4/audit/software";
    private static final String VULNERS_API_SEARCH_ID_PATH = "/api/v3/search/id/";

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final BurpExtender burpExtender;

    HttpClient(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    public JSONObject post(String action, Map<String, String> params) {
        if (burpExtender.isUseApiV4())
            return requestV4("POST", params);
        else
            return request("POST", action, params);
    }

//    public JSONObject postV4(String action, Map<String, String> params) {
//        return requestV4("POST", params);
//    }

    public JSONObject get(String action, Map<String, String> params) {
        return request("GET", action, params);
    }

    public JSONObject request(String method, String action, Map<String, String> params) {
        List<String> headers = new ArrayList<>();
        headers.add( method + " " + VULNERS_API_PATH + action + "/ HTTP/1.1");
        headers.add("Host: " + VULNERS_API_HOST);
        headers.add("User-Agent: Vulners NMAP Plugin 1.3");
        headers.add("Content-type: application/json");

        JSONObject jsonBody = new JSONObject();

        if (!method.equals("GET")) {
            if (burpExtender.getApiKey() != null) {
                jsonBody = jsonBody.put("apiKey", burpExtender.getApiKey());
            }
            else {
                callbacks.printError("[Vulners] requestOld There must be an API key.");
                return new JSONObject();
            }

            for (Map.Entry<String, String> p: params.entrySet()) {
                jsonBody = jsonBody.put(p.getKey(), p.getValue());
            }
        }

        byte[] request = helpers.buildHttpMessage(headers, helpers.stringToBytes(jsonBody.toString()));
        byte[] response = callbacks.makeHttpRequest(VULNERS_API_HOST, 443, true, request);
        return parseResponse(response);
    }

    public JSONObject requestSearchById(List<String> cveID) {

        if (!burpExtender.isSearchForExploits())
        {
            return new JSONObject();
        }

        List<String> headers = new ArrayList<>();
        headers.add( "POST " + VULNERS_API_SEARCH_ID_PATH + "/ HTTP/1.1");
        headers.add("Host: " + VULNERS_API_HOST);
        headers.add("User-Agent: vulners-burpscanner-v-" + VULNERS_BURP_VERSION );
        headers.add("Content-type: application/json");

        JSONObject jsonBody = new JSONObject();

        if (burpExtender.getApiKey() != null) {
            jsonBody = jsonBody.put("apiKey", burpExtender.getApiKey());
        }
        else {
            callbacks.printError("[Vulners] requestSearchByID There must be an API key.");
            return new JSONObject();
        }

        JSONArray fields = new JSONArray("[\n" +
                "    \"id\",\n" +
                "    \"title\",\n" +
                "    \"description\",\n" +
                "    \"type\",\n" +
                "    \"bulletinFamily\",\n" +
                "    \"cvss\"]"
        );

        jsonBody = jsonBody.put("fields", fields);
        jsonBody = jsonBody.put("id", cveID);


        byte[] request = helpers.buildHttpMessage(headers, helpers.stringToBytes(jsonBody.toString()));
        byte[] response = callbacks.makeHttpRequest(VULNERS_API_HOST, 443, true, request);

        String responseString = helpers.bytesToString(response);
        IResponseInfo iResponseInfo = helpers.analyzeResponse(response);
        String jsonString = responseString.substring(iResponseInfo.getBodyOffset());

        JSONObject object = new JSONObject(jsonString);

        if (iResponseInfo.getStatusCode() != 200) {
            callbacks.printOutput("[DEBUG] V4 not OK");
            callbacks.printOutput(jsonString);
            return object;
        }

        return object.optJSONObject("data").optJSONObject("documents");
    }

    public JSONObject requestV4(String method, Map<String, String> params) {
        List<String> headers = new ArrayList<>();
        headers.add( method + " " + VULNERS_API_V4_PATH + "/ HTTP/1.1");
        headers.add("Host: " + VULNERS_API_HOST);
        headers.add("User-Agent: vulners-burpscanner-v-" + VULNERS_BURP_VERSION);
        headers.add("Content-type: application/json");

        JSONObject jsonBody = new JSONObject();
        /*
        * {
"software":[
* {"product":"Angular",
"version":"11.0.0"
}],
"apiKey":""}
        * */
        if (burpExtender.getApiKey() == null) {
            callbacks.printError("[Vulners] requestV4 There must be an API key.");
            return new JSONObject();
        }

        JSONArray fields = new JSONArray("[\"title\"," +
                "\"type\"," +
                "\"short_description\"]"
        );
        jsonBody = jsonBody.put("fields", fields);

        JSONObject softwareDict = new JSONObject();
        switch (params.get("type")){
            case "cpe":
                String[] software=params.get("software").split(":");
                /*
                    "part": "a",
                    "vendor": "ivanti",
                    "product": "connect_secure",
                    "version": "22.7",
                    "update": "r2.4"
                */
                softwareDict.put("part", software[1].substring(1));
                softwareDict.put("vendor", software[2]);
                softwareDict.put("product", software[3]);

                for(String s: software){
                    callbacks.printOutput(s);
                }
                break;
            case "software":
                softwareDict.put("product", params.get("software"));
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
                callbacks.printOutput("[DEBUG] not OK");
                callbacks.printOutput(jsonString);
                return object;
            }
        } catch (Exception e) {
            callbacks.printError("[ERROR]");
            callbacks.printError(jsonString);
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
                callbacks.printOutput("[DEBUG] V4 not OK");
                callbacks.printOutput(jsonString);
            }
            return object;
        } catch (Exception e) {
            callbacks.printError("[ERROR] V4");
            callbacks.printError(jsonString);
            return object;
        }
    }

}
