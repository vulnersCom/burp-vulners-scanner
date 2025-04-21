package burp.gui.software;

import burp.BurpExtender;
import burp.Utils;
import burp.gui.TabComponent;
import burp.gui.path.PathTable;
import burp.gui.vulns.VulnTable;
import burp.models.Domain;
import burp.models.Software;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Map;

class URLSelectionListener extends MouseAdapter{
    private final BurpExtender burpExtender;
    private final TabComponent tabComponent;
    private final PathTable pathTable;

    URLSelectionListener(BurpExtender burpExtender, TabComponent tabComponent, PathTable pathTable){
        this.burpExtender = burpExtender;
        this.tabComponent = tabComponent;
        this.pathTable = pathTable;
    }

    public void mousePressed(MouseEvent event){
        if(event.isConsumed()){
            return;
        }

        JTable table = (JTable) event.getSource();
        int row = table.rowAtPoint(event.getPoint());

        if(row >= 0){
            table.setRowSelectionInterval(row, row);
            int modelRow = table.convertRowIndexToModel(row);
            TableModel model=table.getModel();
            String s = (String) model.getValueAt(row,0);
            Map<String, Domain> domain = burpExtender.getVulnersService().getDomains();
            Domain d = domain.get(s);
            this.pathTable.refreshTable(d);
//            for(String o: d.getSoftware().keySet()){}
            burpExtender.printOutput("[VULNERS] Table view mouse pressed from " + s);
            event.consume();
        }


    }
}

public class SoftwareTable extends JTable {

    private final DefaultTableModel defaultModel;

    public SoftwareTable(BurpExtender burpExtender, TabComponent tabComponent, PathTable pathTable) {
        DefaultTableModel model = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        model.addColumn("Domain");
        model.addColumn("Name");
        model.addColumn("Version");
        model.addColumn("CVSS Score");
        model.addColumn("Vulnerabilities");

        setModel(model);
        this.defaultModel = model;
        this.addMouseListener(new URLSelectionListener(burpExtender, tabComponent, pathTable));

    }

    public void refreshTable(Map<String, Domain> domains , boolean showOnlyVulnerable) {
        defaultModel.setRowCount(0);

        for(String d: domains.keySet()) {
            defaultModel.addRow(new Object[] {
                    d,
                    "s.getValue().getName()",
                    "s.getValue().getVersion()",
                    "Utils.getMaxScore(s.getValue().getVulnerabilities())", //TODO move maxScore field to model
                    "Utils.getVulnersList(s.getValue().getVulnerabilities())"
            });
        }
//        for(Map.Entry<String, Domain> d: domains.entrySet()) {
//            for (Map.Entry<String, Software> s: d.getValue().getSoftware().entrySet()) {
//                if (showOnlyVulnerable && s.getValue().getVulnerabilities().size() <= 0) {
//                    continue;
//                }
//                defaultModel.addRow(new Object[] {
//                        d.getKey(),
//                        s.getValue().getName(),
//                        s.getValue().getVersion(),
//                        Utils.getMaxScore(s.getValue().getVulnerabilities()), //TODO move maxScore field to model
//                        Utils.getVulnersList(s.getValue().getVulnerabilities())
//                });
//            }
//        }
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }
}
