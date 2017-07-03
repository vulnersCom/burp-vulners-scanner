package burp.gui;

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

class RulesTableComponent extends JTable {

    private final DefaultTableModel defaultModel;

    RulesTableComponent() {
        DefaultTableModel model = new DefaultTableModel();
        model.addColumn("Regex");
        model.addColumn("Type");
        model.addColumn("Severity");

        setModel(model);
        this.defaultModel = model;
    }

    DefaultTableModel getDefaultModel() {
        return defaultModel;
    }
}
