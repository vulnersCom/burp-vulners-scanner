package burp.models;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Domain {

    private String name;
    private Map<String, Software> software;
    private Map<String, Set<Vulnerability>> paths;
    private boolean hasVulns=false;
    private double maxCVSS=0.0;

    public Domain() {
        paths = new HashMap<>();
        software = new HashMap<>();
    }

    public String getName() {
        return name;
    }

    public Map<String, Software> getSoftware() {
        return software;
    }

    public Map<String, Set<Vulnerability>> getPaths() {
        return paths;
    }

    public boolean hasVulnerabilities() {
        if(hasVulns)
            return true;

        for(Software s: this.software.values()){
            if(!s.getVulnerabilities().isEmpty()){
                this.hasVulns = true;
                return true;
            }
        }

        for(Set<Vulnerability> e: this.paths.values()){
            if(!e.isEmpty()){
                this.hasVulns = true;
                return true;
            }
        }

        return false;
    }

    // Add results of scanning Software on the specified baseUrl
    public void addSoftwareVulns(String softwareName, String path, Set<Vulnerability> vulnerabilities){
        Software s = this.software.get(softwareName);

        for(Vulnerability v: vulnerabilities){
            s.getVulnerabilities().add(v);
            this.paths.get(path).add(v);
            if(v.getCvssScore() > maxCVSS){
                maxCVSS = v.getCvssScore();
            }
        }
    }

    // Add results of specifically looking at the url and not the software found there
    public void addPathVulns(String path, Set<Vulnerability> vulnerabilities){
        for(Vulnerability v: vulnerabilities){
            this.paths.get(path).add(v);
            if(v.getCvssScore() > maxCVSS){
                maxCVSS = v.getCvssScore();
            }
        }
    }

    public void clear(){
        this.setSoftware(new HashMap<>());
        this.setPaths(new HashMap<>());
        this.hasVulns = false;
        this.maxCVSS = 0;
    }

    public void setSoftware(Map<String, Software> software) {
        this.software = software;
    }

    public void setPaths(Map<String, Set<Vulnerability>> paths) {
        this.paths = paths;
    }

    public double getMaxCVSS() {
        return maxCVSS;
    }
}
