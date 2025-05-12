package burp.gui.vulns;

import burp.BurpExtender;
import burp.gui.TabComponent;
import burp.models.Domain;
import burp.models.Vulnerability;
import com.google.common.collect.Lists;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;


public class VulnTable extends JTable {

    private final DefaultTableModel defaultModel;
    private final ArrayList<String> vulnTypes=Lists.newArrayList();

    public VulnTable(BurpExtender burpExtender, TabComponent tabComponent) {
        DefaultTableModel model = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        model.addColumn("Vulnerability Id");
        model.addColumn("CVSS");

        setModel(model);
        this.defaultModel = model;
        this.addMouseListener(new URLSelectionListener(burpExtender, tabComponent));

    }

    public void refreshTable(Domain domain, String path) {
        if(domain == null){
            clearTable();
            return;
        }

        defaultModel.setRowCount(0);
        vulnTypes.clear();

        // there can be multiple vulns with the same exploits, so create a set not to clog up the table with duplicates
        Set<String> exploits = new HashSet<>();

        for(Vulnerability v: domain.getPaths().get(path)){
            defaultModel.addRow(new Object[]{
                    v.getId(),
                    v.getCvssScore()
            });
            vulnTypes.add(v.getType());

            v.getExploits().stream().map(e -> e[1]).forEach(exploits::add);
        }

        for(String e: exploits){
            defaultModel.addRow(new Object[]{
                    e,
                    "exploit"
            });
            vulnTypes.add("exploit");
        }

    }

    public void clearTable() {
        defaultModel.setRowCount(0);
        vulnTypes.clear();
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }


    class URLSelectionListener extends MouseAdapter{
        private final BurpExtender burpExtender;

        URLSelectionListener(BurpExtender burpExtender, TabComponent tabComponent){
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
                String id = (String) model.getValueAt(modelRow,0);
                String type =  vulnTypes.get(modelRow);

                burpExtender.printOutput("[VULNERS] Table view mouse pressed for " + id + " of type " + type);

                String vulnersLink = String.format("https://vulners.com/%s/%s", type, id);

                if(Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)){
                    try{
                        Desktop.getDesktop().browse(new URI(vulnersLink));
                    } catch (Exception e1) {
                        burpExtender.printError("[VULNERS] Can not open link, please follow " + vulnersLink + " in your browser");
                    }
                }
                else{
                    burpExtender.printError("[VULNERS] Table view Desktop is disabled so please open the link yourself " + vulnersLink);
                }

                event.consume();
            }

        }
    }
}
