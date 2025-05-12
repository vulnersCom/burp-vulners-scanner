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


public class SoftwareTable extends JTable {

    private final DefaultTableModel defaultModel;
    private final PathTable pathTable;
    private final BurpExtender burpExtender;

    public SoftwareTable(BurpExtender burpExtender, TabComponent tabComponent, PathTable pathTable) {
        DefaultTableModel model = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        model.addColumn("Domain");
        model.addColumn("CVSS Score");
        model.addColumn("Vulnerabilities");

        setModel(model);
        this.defaultModel = model;
        this.pathTable = pathTable;
        this.burpExtender = burpExtender;
        this.addMouseListener(new URLSelectionListener());

    }

    public void refreshTable(Map<String, Domain> domains, boolean showOnlyVulnerable) {
        defaultModel.setRowCount(0);

        for(Map.Entry<String, Domain> d: domains.entrySet()) {
            if (showOnlyVulnerable && !d.getValue().hasVulnerabilities()) {
                    continue;
            }
            defaultModel.addRow(new Object[] {
                    d.getKey(),
                    d.getValue().getMaxCVSS(),
                    d.getValue().hasVulnerabilities() ? "true" : "false"
            });
        }
    }

    public void clearTable() {
        defaultModel.setRowCount(0);
        pathTable.clearTable();
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }

    class URLSelectionListener extends MouseAdapter{

        URLSelectionListener(){
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
                String s = (String) model.getValueAt(modelRow,0);
                Map<String, Domain> domain = burpExtender.getVulnersService().getDomains();
                Domain d = domain.get(s);
                pathTable.refreshTable(d);
                burpExtender.printOutput("[VULNERS] Table view mouse pressed from " + s);
                event.consume();
            }


        }
    }
}
