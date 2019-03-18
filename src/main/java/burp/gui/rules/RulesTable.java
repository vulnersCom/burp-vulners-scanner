package burp.gui.rules;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

public class RulesTable extends JTable {

    private final DefaultTableModel defaultModel;

    public RulesTable() {
        DefaultTableModel model = new DefaultTableModel();
        model.addColumn("Software");
        model.addColumn("Regex");
        model.addColumn("Alias");
        model.addColumn("Type");

        setModel(model);
        this.defaultModel = model;
        this.setAutoCreateRowSorter(true);
    }

    public DefaultTableModel getDefaultModel() {
        return defaultModel;
    }
}
