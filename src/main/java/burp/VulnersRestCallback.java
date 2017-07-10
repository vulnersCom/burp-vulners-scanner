package burp;


import burp.models.Vulnerability;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.async.Callback;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashSet;
import java.util.Set;

abstract class VulnersRestCallback implements Callback<JsonNode> {


    private IBurpExtenderCallbacks callbacks;

    VulnersRestCallback(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    /**
     * Rise with response of success returned list of vulnerabilities
     * @param vulnerabilities List of returned vulnerabilities
     */
    public void onScannerSuccess(Set<Vulnerability> vulnerabilities) {

    };

    public void onSuccess(JSONObject data) {
        JSONArray bulletins = data.getJSONArray("search");

        Set<Vulnerability> vulnerabilities = new HashSet<>();
        for (Object bulletin : bulletins) {
            vulnerabilities.add(
                    new Vulnerability(((JSONObject) bulletin).getJSONObject("_source"))
            );
        }

        onScannerSuccess(vulnerabilities);
    }

    /**
     * Rise on error returned or no vulnerabilities found
     */
    public void onFail(JSONObject responseData) {
        callbacks.printError(responseData.getString("error"));
    };

    public void completed(HttpResponse<JsonNode> response) {
        JSONObject responseBody = response.getBody().getObject();

        if ("ERROR".equals(responseBody.getString("result"))) {
            onFail((JSONObject) responseBody.get("data"));
            return;
        }

        onSuccess(responseBody.getJSONObject("data"));
    }

    public void failed(UnirestException e) {
        e.printStackTrace();
    }

    public void cancelled() {}

}
