package burp.gui.path;

import burp.BurpExtender;
import burp.Utils;
import burp.gui.TabComponent;
import burp.gui.software.SoftwareTable;
import burp.gui.vulns.VulnTable;
import burp.models.Domain;
import burp.models.Path;
import burp.models.Software;
import burp.models.Vulnerability;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Map;
import java.util.Set;

public class PathTable extends JTable {

    private final DefaultTableModel defaultModel;
    private final VulnTable vulnTable;
    BurpExtender burpExtender;
    private Domain d=null;

    public PathTable(BurpExtender burpExtender, TabComponent tabComponent, VulnTable vulnTable) {
        DefaultTableModel model = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        model.addColumn("Path");

        setModel(model);
        this.defaultModel = model;
        this.vulnTable = vulnTable;
        this.burpExtender = burpExtender;
        this.addMouseListener(new URLSelectionListener(burpExtender));

    }

    public void refreshTable(Domain domain) {
        defaultModel.setRowCount(0);
        for (Map.Entry<String, Set<Vulnerability>> s: domain.getPaths().entrySet()) {
            if(burpExtender.isShowOnluVuln() && s.getValue().isEmpty())
            {
                continue;
            }
            defaultModel.addRow(new Object[] {
                    s.getKey()
            });
        }
        this.d = domain;
        vulnTable.clearTable();

    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }

    protected Domain getD() { return this.d; }


    class URLSelectionListener extends MouseAdapter{
        private final BurpExtender burpExtender;


        URLSelectionListener(BurpExtender burpExtender){
            this.burpExtender = burpExtender;
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
//            Map<String, Domain> domain = burpExtender.getVulnersService().getDomains();
//            Domain d = domain.get(s);
                Domain d = getD();
                vulnTable.refreshTable(d, s);
//            for(String o: d.getSoftware().keySet()){}
                burpExtender.printOutput("[VULNERS] Table view mouse pressed from " + s);
                event.consume();
            }


        }
    }
}
