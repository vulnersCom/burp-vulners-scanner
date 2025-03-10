package burp;

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
                        return vulnerability.getId();
                    }
                }
        );
    }


    public Set<Vulnerability> getVulnerabilities(JSONObject data) {
        Set<Vulnerability> vulnerabilities = new HashSet<>();

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
            if(!data.get("result").getClass().equals(JSONArray.class))
                return vulnerabilities;

            List<String> cves = new ArrayList<String>();
            for (Object entry : data.getJSONArray("result") ) {

                for (Object vuln: ((JSONObject) entry).getJSONArray("vulnerabilities")) {
                    cves.add(((JSONObject) vuln).getString("id"));

                }

                JSONObject cveInfo = httpClient.requestSearchById(cves);

                for(String cveName: cveInfo.keySet()) {
                    JSONObject bulletin = cveInfo.getJSONObject(cveName);
                    vulnerabilities.add(
                            new Vulnerability(((JSONObject) bulletin))
                    );
                }
            }
        }
        return vulnerabilities;
    }
}
