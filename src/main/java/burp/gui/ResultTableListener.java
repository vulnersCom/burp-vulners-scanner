package burp.gui;

import burp.IBurpExtenderCallbacks;
import com.codemagi.burp.MatchRule;
import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import java.io.*;
import java.net.URL;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;


public class ResultTableListener implements TableModelListener {

    private static final String DEFAULT_URL = "https://raw.githubusercontent.com/augustd/burp-suite-software-version-checks/master/src/main/resources/burp/match-rules.tab";

    private IBurpExtenderCallbacks mCallbacks;
    private DefaultTableModel model;
    private PassiveScan scan;

    public ResultTableListener(IBurpExtenderCallbacks callbacks, DefaultTableModel model, PassiveScan scan) {
        this.mCallbacks = callbacks;
        this.model = model;
        this.scan = scan;

        // Load match rules from vulners.com
        loadMatchRules(DEFAULT_URL);
    }

    @Override
    public void tableChanged(TableModelEvent e) {
        if (TableModelEvent.UPDATE == e.getType()) {
            this.onTableChage(e);
        }
    }

    private void onTableChage(TableModelEvent e) {
        mCallbacks.printOutput(e.toString());
        int row = e.getFirstRow();
        int column = e.getColumn();
        mCallbacks.printOutput("row: " + row + " column: " + column + " value: " + model.getValueAt(row, column));
        MatchRule rule = scan.getMatchRule(row);
        mCallbacks.printOutput("rule 1: " + rule);
        if (rule == null) {
            rule = new MatchRule(Pattern.compile("."), 1, "", ScanIssueSeverity.LOW, ScanIssueConfidence.CERTAIN);
            scan.addMatchRule(rule);
        }
        mCallbacks.printOutput("rule 2: " + rule);

        switch (column) {
            case 0:
                mCallbacks.printOutput("new pattern: " + (String)model.getValueAt(row, column));
                rule.setPattern(Pattern.compile((String)model.getValueAt(row, column)));
                break;
            case 1:
                rule.setMatchGroup((Integer)model.getValueAt(row, column));
                break;
            case 2:
                rule.setType((String)model.getValueAt(row, column));
                break;
            case 3:
                rule.setSeverity(ScanIssueSeverity.fromName((String)model.getValueAt(row, column)));
                break;
            case 4:
                rule.setConfidence(ScanIssueConfidence.fromName((String)model.getValueAt(row, column)));
                break;
        }
    }


    /**
     * Load match rules from a file
     */
    private void loadMatchRules(String url) {
        //load match rules from file
        try {

            //read match rules from the stream
            InputStream is = new URL(url).openStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));

            String str;
            while ((str = reader.readLine()) != null) {
                mCallbacks.printOutput("str: " + str);
                if (str.trim().length() == 0) {
                    continue;
                }

                String[] values = str.split("\\t");
                this.model.addRow(values);

                try {
                    Pattern pattern = Pattern.compile(values[0]);

                    scan.addMatchRule(new MatchRule(
                            pattern,
                            new Integer(values[1]),
                            values[2],
                            ScanIssueSeverity.fromName(values[3]),
                            ScanIssueConfidence.fromName(values[4]))
                    );
                } catch (PatternSyntaxException pse) {
                    mCallbacks.printError("Unable to compile pattern: " + values[0] + " for: " + values[2]);
                    scan.printStackTrace(pse);
                }
            }

        } catch (Exception e) {
            OutputStream error = mCallbacks.getStderr();
            e.printStackTrace(new PrintStream(error));
        }

    }

}
