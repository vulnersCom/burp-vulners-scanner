package burp;


import burp.models.Vulnerability;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashSet;
import java.util.Set;

abstract class VulnersRestCallback {

    private IBurpExtenderCallbacks callbacks;

    VulnersRestCallback(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    /**
     * Rise with response of success returned list of vulnerabilities
     *
     * @param vulnerabilities List of returned vulnerabilities
     */
    public void onScannerSuccess(Set<Vulnerability> vulnerabilities) {

    }

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
    public void onFail(String error) {
        callbacks.printError(error);
    }
}
