package burp.gui.path;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

public class PathsTable extends JTable {

    private final DefaultTableModel defaultModel;

    public PathsTable() {
        DefaultTableModel model = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        model.addColumn("Domain");
        model.addColumn("path");
        model.addColumn("CVSS Score");
        model.addColumn("Vulnerabilities");

        setModel(model);
        this.defaultModel = model;
        this.setAutoCreateRowSorter(true);
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }
}
