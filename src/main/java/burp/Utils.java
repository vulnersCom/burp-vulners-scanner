package burp;

import burp.models.Vulnerability;
import com.google.common.base.Function;
import com.google.common.collect.Collections2;
import com.google.common.collect.Ordering;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by vankyver on 05/07/2017.
 */
public class Utils {

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


    public static Set<Vulnerability> getVulnerabilities(JSONObject data) {
        Set<Vulnerability> vulnerabilities = new HashSet<>();

        if (!data.has("search")) {
            return vulnerabilities;
        }

        JSONArray bulletins = data.getJSONArray("search");
        for (Object bulletin : bulletins) {
            vulnerabilities.add(
                    new Vulnerability(((JSONObject) bulletin).getJSONObject("_source"))
            );
        }
        return vulnerabilities;
    }
}
