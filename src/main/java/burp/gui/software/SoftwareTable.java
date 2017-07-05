package burp.gui.software;

import burp.Utils;
import burp.models.Domain;
import burp.models.Software;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.Map;

public class SoftwareTable extends JTable {

    private final DefaultTableModel defaultModel;

    public SoftwareTable() {
        DefaultTableModel model = new DefaultTableModel();
        model.addColumn("Domain");
        model.addColumn("Name");
        model.addColumn("Version");
        model.addColumn("CVSS Score");
        model.addColumn("Vulnerabilities");

        setModel(model);
        this.defaultModel = model;
    }

    public void refreshTable(Map<String, Domain> domains , boolean showNotVulnerable) {
        defaultModel.setRowCount(0);
        for(Map.Entry<String, Domain> d: domains.entrySet()) {
            for (Map.Entry<String, Software> s: d.getValue().getSoftware().entrySet()) {
                if (!showNotVulnerable && s.getValue().getVulnerabilities().size() <= 0) {
                    continue;
                }
                defaultModel.addRow(new Object[] {
                        d.getKey(),
                        s.getValue().getName(),
                        s.getValue().getVersion(),
                        Utils.getMaxScore(s.getValue().getVulnerabilities()), //TODO move maxScore field to model
                        ""
                });
            }
        }
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }
}
