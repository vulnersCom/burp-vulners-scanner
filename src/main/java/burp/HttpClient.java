package burp;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class HttpClient {

    private static String VULNERS_API_HOST = "vulners.com";
    private static String VULNERS_API_PATH = "/api/v3/burp/";

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final BurpExtender burpExtender;

    HttpClient(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    public JSONObject get(String action, Map<String, String> params) {
        List<String> headers = new ArrayList<>();
        headers.add("POST " + VULNERS_API_PATH + action + "/ HTTP/1.1");
        headers.add("Host: " + VULNERS_API_HOST);
        headers.add("User-Agent: vulners-burpscanner-v-1.2");
        headers.add("Content-type: application/json");

        JSONObject jsonBody = new JSONObject();

        if (burpExtender.getApiKey() != null) {
            jsonBody = jsonBody.put("apiKey", burpExtender.getApiKey());
        }

        for (Map.Entry<String, String> p: params.entrySet()) {
            jsonBody = jsonBody.put(p.getKey(), p.getValue());
        }

        byte[] request = helpers.buildHttpMessage(headers, helpers.stringToBytes(jsonBody.toString()));
        byte[] response = callbacks.makeHttpRequest(VULNERS_API_HOST, 443, true, request);
        return parseResponse(response);
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

}
