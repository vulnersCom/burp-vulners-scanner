package burp.models;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by vankyver on 03/07/2017.
 */
public class Domain {

    private String name;
    private Map<String, Software> software;

    public Domain() {
        software = new HashMap<>();
    }

    public String getName() {
        return name;
    }

    public Map<String, Software> getSoftware() {
        return software;
    }
}
