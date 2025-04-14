package burp.gui.vulns;

import burp.BurpExtender;
import burp.Utils;
import burp.gui.TabComponent;
import burp.models.Domain;
import burp.models.Software;
import burp.models.Vulnerability;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Map;

import java.net.URI;

class URLSelectionListener extends MouseAdapter{
    private final BurpExtender burpExtender;
    private final TabComponent tabComponent;

    URLSelectionListener(BurpExtender burpExtender, TabComponent tabComponent){
        this.burpExtender = burpExtender;
        this.tabComponent = tabComponent;
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
            String id = (String) model.getValueAt(row,0);
            String type = (String) model.getValueAt(row,1);
            burpExtender.printOutput("[VULNERS] Table view mouse pressed for " + id);

            String vulnersLink = String.format("https://vulners.com/%s/%s", type, id);

            if(Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)){
                try{
                    Desktop.getDesktop().browse(new URI(vulnersLink));
                } catch (Exception e1) {
                    burpExtender.printError("[Vulners] Can not open link, please follow " + vulnersLink + " in your browser");
                }
            }
            else{
                burpExtender.printOutput("[VULNERS] Table view Desktop is disabled so please open the link yourself " + vulnersLink);
            }

            event.consume();
        }


    }
}

public class VulnTable extends JTable {

    private final DefaultTableModel defaultModel;

    public VulnTable(BurpExtender burpExtender, TabComponent tabComponent) {
        DefaultTableModel model = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        model.addColumn("Vulnerability Id");
        model.addColumn("Type");


        setModel(model);
        this.defaultModel = model;
        this.addMouseListener(new URLSelectionListener(burpExtender, tabComponent));

    }

    public void refreshTable(Domain domain) {

        defaultModel.setRowCount(0);
//        for(Map.Entry<String, Domain> d: domains.entrySet()) {
//            for (Map.Entry<String, Software> s: d.getValue().getSoftware().entrySet()) {
//                if (showOnlyVulnerable && s.getValue().getVulnerabilities().size() <= 0) {
//                    continue;
//                }
//                defaultModel.addRow(new Object[] {
////                        d.getKey(),
//                        s.getValue().getName(),
////                        s.getValue().getVersion(),
////                        Utils.getMaxScore(s.getValue().getVulnerabilities()), //TODO move maxScore field to model
////                        Utils.getVulnersList(s.getValue().getVulnerabilities())
//                });
//            }
        for(Map.Entry<String, Software> s: domain.getSoftware().entrySet()){
//            defaultModel.addRow(new Object[]{
//////                        d.getKey(),
//                        s.getValue().getName()
//            });
            for(Vulnerability v: s.getValue().getVulnerabilities()){
                defaultModel.addRow(new Object[]{
////                        d.getKey(),
                        v.getId(),
                        v.getType()
                });
            }
        }
//        }
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }
}
