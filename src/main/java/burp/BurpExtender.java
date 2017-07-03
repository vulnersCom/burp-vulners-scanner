package burp;

import burp.gui.RulesComponent;
import burp.models.Domain;
import burp.models.Software;
import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.ScannerMatch;
import com.monikamorrow.burp.BurpSuiteTab;

import java.util.*;


public class BurpExtender extends PassiveScan {

    private Map<String, Domain> domains = new HashMap<>();
    private VulnersService vulnersService;

    @Override
    protected void initPassiveScan() {
        extensionName = "Vulners Scanner";
        settingsNamespace = "VULNERS_";

        BurpSuiteTab mTab = new BurpSuiteTab("Vulners Scanner", callbacks);
        mTab.addComponent(new RulesComponent(this, callbacks).getRootPanel());

        vulnersService = new VulnersService(callbacks, helpers, domains);
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
                    match.getMatchGroup());

            domains.get(domainName)
                    .getSoftware()
                    .put(software.getKey(), software);

            //add a marker for code highlighting
            startStop.add(new int[]{match.getStart(), match.getEnd()});

            vulnersService.checkSoftware(domainName, software, baseRequestResponse, startStop, matches);
        }

        return new ArrayList<>();
    }

    @Override
    protected IScanIssue getScanIssue(IHttpRequestResponse baseRequestResponse, List<ScannerMatch> matches, List<int[]> startStop) {
        return new SoftwareIssue(baseRequestResponse, helpers, callbacks, startStop, new Software("", "", "")); //TODO
    }

}