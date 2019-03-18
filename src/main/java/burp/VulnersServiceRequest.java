package burp;

import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.google.common.base.Charsets.UTF_8;

class VulnersServiceRequest {
    private static String BURP_API_URL = "https://vulners.com/api/v3/burp/{path}/";

    private final IBurpExtenderCallbacks callbacks;
    private String pathParameter;
    private final Map<String, String> queryStringParameters;

    private VulnersServiceRequest(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.queryStringParameters = new HashMap<>();
    }

    static VulnersServiceRequest vulnersRestServiceGetRequest(IBurpExtenderCallbacks callbacks) {
        return new VulnersServiceRequest(callbacks);
    }

    VulnersServiceRequest pathParameter(String value) {
        pathParameter = value;
        return this;
    }

    VulnersServiceRequest queryString(String name, String value) {
        queryStringParameters.put(name, value);
        return this;
    }

    void send(VulnersRestCallback callback) {
        IExtensionHelpers helpers = callbacks.getHelpers();
        URL url = url();
        byte[] request = helpers.buildHttpRequest(url);
        request = addHeader(request, "user-agent: vulners-burpscanner-v-1.0-DEMO");

        try {
            IHttpRequestResponse httpRequestResponse = callbacks.makeHttpRequest(urlToHttpService(url), request);
            byte[] response = httpRequestResponse.getResponse();
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            String body = new String(response, responseInfo.getBodyOffset(), response.length - responseInfo.getBodyOffset(), UTF_8);
            JSONObject bodyAsJson = new JSONObject(body);

            if ("OK".equalsIgnoreCase(bodyAsJson.getString("result"))) {
                callback.onSuccess(bodyAsJson.getJSONObject("data"));
            } else {
                callback.onFail(bodyAsJson.getString("error"));
            }
        } catch (Exception e) {
            callbacks.printError(String.format("Unexpected error issuing request to %s", url));
        }
    }

    URL url() {
        try {
            return new URL(BURP_API_URL.replace("{path}", pathParameter) + buildQueryString());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private IHttpService urlToHttpService(URL url) {
        boolean isHttps = url.getProtocol().equals("https");
        int port = url.getPort();
        if (port == -1) {
            port = isHttps ? 443 : 80;
        }
        return callbacks.getHelpers().buildHttpService(url.getHost(), port, isHttps);
    }

    private String buildQueryString() {
        if (queryStringParameters.isEmpty()) {
            return "";
        }
        StringBuilder stringBuilder = new StringBuilder("?");
        for (Map.Entry<String, String> entry : queryStringParameters.entrySet()) {
            stringBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        }
        return stringBuilder.substring(0, stringBuilder.length() - 1);
    }

    private byte[] addHeader(byte[] request, String header) {
        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        headers.add(header);
        byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        return callbacks.getHelpers().buildHttpMessage(headers, body);
    }
}
