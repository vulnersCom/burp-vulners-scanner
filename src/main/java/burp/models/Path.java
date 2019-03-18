package burp.models;

import java.util.Set;

public class Path {

    private String key;
    private Set<Vulnerability> vulnerability;

    public String getKey() {
        return key;
    }

    public Set<Vulnerability> getVulnerability() {
        return vulnerability;
    }
}
