package burp.models;

import java.util.HashSet;
import java.util.Set;

public class Software {

    private String key;
    private String name;
    private String version;
    private Set<Vulnerability> vulnerabilities;

    public Software(String key, String name, String version) {
        this.key = key;
        this.name = name;
        this.version = version;
        this.vulnerabilities = new HashSet<>();
    }

    public String getKey() {
        return key;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public Set<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

}
