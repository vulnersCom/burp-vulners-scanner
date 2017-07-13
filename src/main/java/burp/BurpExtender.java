package burp;

import burp.gui.TabComponent;
import burp.models.Domain;
import burp.models.Software;
import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.ScannerMatch;
import com.monikamorrow.burp.BurpSuiteTab;

import java.net.URL;
import java.util.*;


public class BurpExtender extends PassiveScan {

    private TabComponent tabComponent;
    private VulnersService vulnersService;
    private Map<String, Domain> domains = new HashMap<>();
    private Map<String, Map<String, String>> matchRules = new HashMap<>();

    @Override
    protected void initPassiveScan() {
        extensionName = "Software Vulnerability Scanner";
        settingsNamespace = "VULNERS_";

        BurpSuiteTab mTab = new BurpSuiteTab("Software Vulnerability Scanner", callbacks);
        this.tabComponent = new TabComponent(this, callbacks, domains);

        mTab.addComponent(tabComponent.getRootPanel());

        vulnersService = new VulnersService(this, callbacks, helpers, domains, tabComponent);
        vulnersService.loadRules();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = super.doPassiveScan(baseRequestResponse);

        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();

        /*
         * Here we check possible vulnerabilities related on request path
         */
        if ((tabComponent.getCbxPathScanInScope().isSelected() && !callbacks.isInScope(url)) || !tabComponent.getCbxPathSearch().isSelected()) {
            return issues;
        }

        String domainName = url.getHost();
        String path = url.getPath();
        Domain domain = domains.get(domainName);
        if (domain == null) {
            domains.put(domainName, domain = new Domain());
        }

        if (!domain.getPaths().containsKey(path)) {
            callbacks.printOutput("[Vulners] adding new path '" + path + "' for domain " + domainName);
            domain.getPaths().put(path, null);
            vulnersService.checkURLPath(domainName, path, baseRequestResponse);
        }

        return issues;
    }

    @Override
    protected List<IScanIssue> processIssues(List<ScannerMatch> matches, IHttpRequestResponse baseRequestResponse) {
        if (matches.isEmpty()) {
            return super.processIssues(matches, baseRequestResponse);
        }

        String domainName = helpers.analyzeRequest(baseRequestResponse).getUrl().getHost();
        List<int[]> startStop = new ArrayList<>(1);
        callbacks.printOutput("[Vulners] Processing issues for: " + domainName);


        //get the existing matches for this domain
        Domain domain = domains.get(domainName);
        if (domain == null) {
            domains.put(domainName, domain = new Domain());
        }

        Collections.sort(matches); //matches must be in order
        for (ScannerMatch match : matches) {
            if (domain.getSoftware().get(match.getType() + match.getMatchGroup()) != null) {
                continue;
            }

            Software software = new Software(
                    match.getType() + match.getMatchGroup(),
                    match.getType(),
                    match.getMatchGroup(),

                    matchRules.get(match.getType()).get("type"),
                    matchRules.get(match.getType()).get("alias")
            );

            domains.get(domainName)
                    .getSoftware()
                    .put(software.getKey(), software);

            //add a marker for code highlighting
            startStop.add(new int[]{match.getStart(), match.getEnd()});

            vulnersService.checkSoftware(domainName, software, baseRequestResponse, startStop);
        }

        return new ArrayList<>();
    }

    @Override
    protected IScanIssue getScanIssue(IHttpRequestResponse baseRequestResponse, List<ScannerMatch> matches, List<int[]> startStop) {
        return new SoftwareIssue(baseRequestResponse, helpers, callbacks, startStop, new Software("", "", "", "", "")); //TODO
    }

    public VulnersService getVulnersService() {
        return vulnersService;
    }

    Map<String, Map<String, String>> getMatchRules() {
        return matchRules;
    }
}