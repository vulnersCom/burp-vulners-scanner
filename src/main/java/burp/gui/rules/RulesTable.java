package burp.gui.rules;

import burp.IBurpExtenderCallbacks;
import com.codemagi.burp.MatchRule;
import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.io.*;
import java.net.URL;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class RulesTable extends JTable {

    private final DefaultTableModel defaultModel;

    public RulesTable() {
        DefaultTableModel model = new DefaultTableModel();
        model.addColumn("Software");
        model.addColumn("Regex");
        model.addColumn("Alias");
        model.addColumn("Type");

        setModel(model);
        this.defaultModel = model;
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }
}
