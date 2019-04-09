package burp.gui.rules;

import burp.IBurpExtenderCallbacks;
import com.codemagi.burp.MatchRule;
import com.codemagi.burp.PassiveScan;
import com.codemagi.burp.ScanIssueConfidence;
import com.codemagi.burp.ScanIssueSeverity;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import java.awt.event.ActionEvent;
import java.util.regex.Pattern;


public class RulesTableListener implements TableModelListener {

    private final JTable table;

    private IBurpExtenderCallbacks mCallbacks;
    private DefaultTableModel model;
    private PassiveScan scan;

    public RulesTableListener(IBurpExtenderCallbacks callbacks, JTable table, DefaultTableModel model, PassiveScan scan) {
        this.mCallbacks = callbacks;
        this.table = table;
        this.model = model;
        this.scan = scan;
    }

    @Override
    public void tableChanged(TableModelEvent e) {
        if (TableModelEvent.UPDATE == e.getType()) {
            this.onTableChage(e);
        }
    }

    private void onTableChage(TableModelEvent e) {
        int row = e.getFirstRow();
        int column = e.getColumn();
        MatchRule rule = scan.getMatchRule(row);
        if (rule == null) {
            rule = new MatchRule(Pattern.compile("."), 1, "", ScanIssueSeverity.LOW, ScanIssueConfidence.CERTAIN);
            scan.addMatchRule(rule);
        }

        switch (column) {
            case 0:
                mCallbacks.printOutput("[Vulners] new pattern: " + (String)model.getValueAt(row, column));
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


    public void onAddButtonClick(ActionEvent e) {
        model.addRow(new Object[]{"", 1, "", "Low", "Certain"});
    }

    public void onRemoveButtonClick(ActionEvent e) {
        int[] rows = table.getSelectedRows();
        for (int i = 0; i < rows.length; i++) {
            model.removeRow(rows[i] - i);
            scan.removeMatchRule(rows[i] - i);
        }
    }

}
