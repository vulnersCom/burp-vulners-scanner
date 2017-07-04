package burp.gui.path;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

public class PathsTable extends JTable {

    private final DefaultTableModel defaultModel;

    public PathsTable() {
        DefaultTableModel model = new DefaultTableModel();
        model.addColumn("Domain");
        model.addColumn("path");
        model.addColumn("CVSS Score");
        model.addColumn("Vulnerabilities");

        setModel(model);
        this.defaultModel = model;
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }
}
