package burp;

import burp.models.PathVulnerability;
import burp.models.Vulnerability;
import com.google.common.base.Function;
import com.google.common.collect.Collections2;
import com.google.common.collect.Ordering;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

/**
 * Created by vankyver on 05/07/2017.
 */
public class Utils {

    private HttpClient httpClient;

    public Utils(HttpClient client) {
        this.httpClient = client;
    }

    public static Double getMaxScore(Set<Vulnerability> vulnerabilities) {
        if (vulnerabilities.size() <= 0) {
            return null;
        }

        Collection<Double> scores = Collections2.transform(
                vulnerabilities, new Function<Vulnerability, Double>() {
                    @Override
                    public Double apply(Vulnerability vulnerability) {
                        return vulnerability.getCvssScore();
                    }
                }
        );
        return Ordering.natural().max(scores);
    }

    public static Collection<String> getVulnersList(Set<Vulnerability> vulnerabilities) {
        if (vulnerabilities.size() <= 0) {
            return null;
        }

        return Collections2.transform(
                vulnerabilities, new Function<Vulnerability, String>() {
                    @Override
                    public String apply(Vulnerability vulnerability) {
//                        return vulnerability.getId();
                        return vulnerability.getItemLink();
                    }
                }
        );
    }

    public Set<Vulnerability> getPathVulnerabilities(JSONObject data) {
        Set<Vulnerability> vulnerabilities=new HashSet<>();
//        Map<String, Set<Vulnerability>> lVulnerabilities = new HashMap<>();

        // Use new API V4
        if(!data.has("result") || !data.get("result").getClass().equals(JSONObject.class))
            return new HashSet<>();
        data = data.getJSONObject("result");
        for (String path : data.keySet() ) {
            JSONArray vulns = data.getJSONArray(path);
            vulns.forEach(v -> {
                vulnerabilities.add(PathVulnerability.fromWebVulns(path, (JSONObject) v));
            });
        }

//        vulnerabilities.addAll(lVulnerabilities.values());

        return vulnerabilities;
    }


    public Set<Vulnerability> getVulnerabilities(JSONObject data) {
        Set<Vulnerability> vulnerabilities = new HashSet<>();
        Map<String, Vulnerability> lVulnerabilities = new HashMap<>();

        // Parse OLD Api
        if (data.has("search")) {
            JSONArray bulletins = data.getJSONArray("search");
            for (Object bulletin : bulletins) {
                vulnerabilities.add(
                        new Vulnerability(((JSONObject) bulletin).getJSONObject("_source"))
                );
            }
        } else {
            // Use new API V4
            if(!data.has("result") || !data.get("result").getClass().equals(JSONArray.class))
                return vulnerabilities;

            String cveId;
            for (Object entry : data.getJSONArray("result") ) {
                for (Object vuln: ((JSONObject) entry).getJSONArray("vulnerabilities")) {
                    cveId = ((JSONObject) vuln).getString("id");
                    lVulnerabilities.put(cveId, Vulnerability.fromAuditV4((JSONObject) vuln));
                }
            }

            vulnerabilities.addAll(lVulnerabilities.values());
        }

        return vulnerabilities;
    }

}
