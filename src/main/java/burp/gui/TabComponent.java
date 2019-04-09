package burp.gui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.gui.path.PathsTable;
import burp.gui.rules.RulesTable;
import burp.gui.rules.RulesTableListener;
import burp.gui.software.SoftwareTable;
import burp.models.Domain;
import burp.models.Software;
import burp.models.Vulnerability;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class TabComponent {
    private JPanel rootPanel;
    private JButton btnRuleAdd;
    private JButton btnRuleRemove;
    private JButton btnRulesLoad;
    private JTextField txtRulesURL;
    private JScrollPane scrlPanel;
    private BurpExtender burpExtender;
    private IBurpExtenderCallbacks callbacks;
    private JTable tblRules;
    private JTable tblSoftware;
    private JTable tblPaths;
    private JCheckBox cbxPathSearch;
    private JButton btnTblSoftwareClear;
    private JButton btnTblPathClear;
    private JCheckBox cbxSoftwareShowVuln;
    private JTabbedPane tabbedPane1;
    private JTextField tbxReqLimit;
    private JCheckBox cbxPathScanInScope;
    private JTextField txtApi;
    private JLabel linkLabel;
    private JButton btnApi;

    private RulesTable rulesTable;
    private PathsTable pathsTable;
    private SoftwareTable softwareTable;
    private final Map<String, Domain> domains;

    public TabComponent(final BurpExtender burpExtender, final IBurpExtenderCallbacks callbacks, final Map<String, Domain> domains) {
        this.burpExtender = burpExtender;
        this.callbacks = callbacks;
        this.domains = domains;

        $$$setupUI$$$();

        /*
         * Rules Table and support Buttons
         */
        final RulesTableListener ruleTableListener = new RulesTableListener(callbacks, this.tblRules, this.rulesTable.getDefaultModel(), burpExtender);
        this.tblRules.getModel().addTableModelListener(ruleTableListener);


        btnApi.addActionListener(e -> new Thread(() -> burpExtender.setApiKey(txtApi.getText())).start());

        btnRuleAdd.addActionListener(e -> new Thread(() -> ruleTableListener.onAddButtonClick(e)).start());

        btnRuleRemove.addActionListener(e -> new Thread(() -> ruleTableListener.onRemoveButtonClick(e)).start());

        btnRulesLoad.addActionListener(e -> new Thread(() -> {
            try {
                burpExtender.getVulnersService().loadRules();
            } catch (IOException e1) {
                callbacks.printError(e1.getMessage());
            }
        }).start());

        btnTblPathClear.addActionListener(e -> {
            for (Map.Entry<String, Domain> d : domains.entrySet()) {
                d.getValue().setPaths(new HashMap<>());
            }
            pathsTable.getDefaultModel().setRowCount(0);
        });

        btnTblSoftwareClear.addActionListener(e -> {
            for (Map.Entry<String, Domain> d : domains.entrySet()) {
                d.getValue().setSoftware(new HashMap<>());
            }
            softwareTable.getDefaultModel().setRowCount(0);
        });

        cbxSoftwareShowVuln.addActionListener(e -> softwareTable.refreshTable(domains, cbxSoftwareShowVuln.isSelected()));

        linkLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String vulnersLink = "https://vulners.com/landing#login";
                try {
                    Desktop.getDesktop().browse(new URI(vulnersLink));
                } catch (Exception e1) {
                    callbacks.printError("[Vulners] Can not open link, please follow " + vulnersLink + " in your browser");
                }
            }
        });
    }

    /**
     * Creates Custom GUI forms
     */
    private void createUIComponents() {
        tblRules = rulesTable = new RulesTable();
        tblPaths = pathsTable = new PathsTable();
        tblSoftware = softwareTable = new SoftwareTable();
    }

    public JPanel getRootPanel() {
        return rootPanel;
    }

    public PathsTable getPathsTable() {
        return pathsTable;
    }

    public SoftwareTable getSoftwareTable() {
        return softwareTable;
    }

    public JCheckBox getCbxPathSearch() {
        return cbxPathSearch;
    }

    public JCheckBox getCbxSoftwareShowVuln() {
        return cbxSoftwareShowVuln;
    }

    public JCheckBox getCbxPathScanInScope() {
        return cbxPathScanInScope;
    }

    public RulesTable getRulesTable() {
        return rulesTable;
    }

    public void setAPIKey(String apiKey) {
        if (apiKey != null) {
            txtApi.setText(apiKey);
        }
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        createUIComponents();
        rootPanel = new JPanel();
        rootPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        tabbedPane1 = new JTabbedPane();
        tabbedPane1.setTabPlacement(1);
        rootPanel.add(tabbedPane1);
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(5, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Scan rules", panel1);
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(3, 2, new Insets(10, 0, 0, 0), -1, -1));
        panel1.add(panel2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        Font label1Font = this.$$$getFont$$$(null, Font.BOLD, 14, label1.getFont());
        if (label1Font != null) label1.setFont(label1Font);
        label1.setText("Software vulnerability scanner");
        panel2.add(label1, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Uses vulners.com API to detect vulnerabilities in flagged version of software.");
        panel2.add(label2, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        Font label3Font = this.$$$getFont$$$(null, Font.BOLD, -1, label3.getFont());
        if (label3Font != null) label3.setFont(label3Font);
        label3.setHorizontalAlignment(2);
        label3.setIcon(new ImageIcon(getClass().getResource("/logo_small.png")));
        label3.setText("");
        panel2.add(label3, new GridConstraints(0, 0, 3, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(-1, 60), new Dimension(-1, 60), 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Match rules use regular expressions to flag software version numbers in server responses. ");
        panel2.add(label4, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        scrlPanel = new JScrollPane();
        panel1.add(scrlPanel, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        tblRules.setAutoCreateRowSorter(true);
        scrlPanel.setViewportView(tblRules);
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(3, 4, new Insets(20, 0, 0, 0), -1, -1));
        panel1.add(panel3, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        Font label5Font = this.$$$getFont$$$(null, Font.BOLD, 14, label5.getFont());
        if (label5Font != null) label5.setFont(label5Font);
        label5.setText("API Token   ");
        panel3.add(label5, new GridConstraints(0, 0, 1, 3, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("Provide you persanal API token to improve scan speed while using vulners.com api");
        panel3.add(label6, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnApi = new JButton();
        btnApi.setText("Add");
        panel3.add(btnApi, new GridConstraints(2, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, new Dimension(70, 27), new Dimension(70, 27), new Dimension(70, 27), 0, false));
        txtApi = new JTextField();
        txtApi.setText("");
        panel3.add(txtApi, new GridConstraints(2, 0, 1, 3, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        linkLabel = new JLabel();
        Font linkLabelFont = this.$$$getFont$$$(null, Font.PLAIN, -1, linkLabel.getFont());
        if (linkLabelFont != null) linkLabel.setFont(linkLabelFont);
        linkLabel.setForeground(new Color(-15259748));
        linkLabel.setText("get token...");
        panel3.add(linkLabel, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(2, 2, new Insets(20, 0, 0, 0), -1, -1));
        panel1.add(panel4, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        btnRulesLoad = new JButton();
        btnRulesLoad.setText("Load");
        panel4.add(btnRulesLoad, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, new Dimension(70, 27), new Dimension(70, 27), new Dimension(70, 27), 0, false));
        txtRulesURL = new JTextField();
        txtRulesURL.setText("https://vulners.com/api/v3/burp/rules");
        panel4.add(txtRulesURL, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label7 = new JLabel();
        Font label7Font = this.$$$getFont$$$(null, Font.BOLD, 14, label7.getFont());
        if (label7Font != null) label7.setFont(label7Font);
        label7.setText("Scan Rules");
        panel4.add(label7, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel5, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        btnRuleRemove = new JButton();
        btnRuleRemove.setText("Remove");
        panel5.add(btnRuleRemove, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnRuleAdd = new JButton();
        btnRuleAdd.setText("Add");
        panel5.add(btnRuleAdd, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel5.add(spacer1, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new GridLayoutManager(8, 2, new Insets(10, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Results", panel6);
        final JScrollPane scrollPane1 = new JScrollPane();
        panel6.add(scrollPane1, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(454, 126), null, 0, false));
        tblSoftware.setAutoCreateRowSorter(true);
        scrollPane1.setViewportView(tblSoftware);
        btnTblSoftwareClear = new JButton();
        btnTblSoftwareClear.setText("Clear");
        panel6.add(btnTblSoftwareClear, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label8 = new JLabel();
        Font label8Font = this.$$$getFont$$$(null, Font.BOLD, -1, label8.getFont());
        if (label8Font != null) label8.setFont(label8Font);
        label8.setText("Vulnerable Software");
        panel6.add(label8, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel6.add(spacer2, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        cbxSoftwareShowVuln = new JCheckBox();
        cbxSoftwareShowVuln.setSelected(false);
        cbxSoftwareShowVuln.setText("Show only vulnerable software");
        panel6.add(cbxSoftwareShowVuln, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JSeparator separator1 = new JSeparator();
        panel6.add(separator1, new GridConstraints(4, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JLabel label9 = new JLabel();
        Font label9Font = this.$$$getFont$$$(null, Font.BOLD, -1, label9.getFont());
        if (label9Font != null) label9.setFont(label9Font);
        label9.setText("Possible vulnerable software uses specific paths");
        panel6.add(label9, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane2 = new JScrollPane();
        panel6.add(scrollPane2, new GridConstraints(6, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(454, 126), null, 0, false));
        tblPaths.setAutoCreateRowSorter(true);
        scrollPane2.setViewportView(tblPaths);
        btnTblPathClear = new JButton();
        btnTblPathClear.setText("Clear");
        panel6.add(btnTblPathClear, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new GridLayoutManager(4, 2, new Insets(10, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Options", panel7);
        final JLabel label10 = new JLabel();
        Font label10Font = this.$$$getFont$$$(null, Font.BOLD, -1, label10.getFont());
        if (label10Font != null) label10.setFont(label10Font);
        label10.setText("Scan options");
        panel7.add(label10, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cbxPathSearch = new JCheckBox();
        cbxPathSearch.setEnabled(true);
        cbxPathSearch.setSelected(false);
        cbxPathSearch.setText("");
        panel7.add(cbxPathSearch, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(51, 20), null, 0, false));
        final JLabel label11 = new JLabel();
        label11.setText("Use scan by locations paths");
        panel7.add(label11, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer3 = new Spacer();
        panel7.add(spacer3, new GridConstraints(3, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JLabel label12 = new JLabel();
        label12.setText("Scope Only");
        panel7.add(label12, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_EAST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cbxPathScanInScope = new JCheckBox();
        cbxPathScanInScope.setEnabled(true);
        cbxPathScanInScope.setSelected(true);
        cbxPathScanInScope.setText("");
        panel7.add(cbxPathScanInScope, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(51, 20), null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    private Font $$$getFont$$$(String fontName, int style, int size, Font currentFont) {
        if (currentFont == null) return null;
        String resultName;
        if (fontName == null) {
            resultName = currentFont.getName();
        } else {
            Font testFont = new Font(fontName, Font.PLAIN, 10);
            if (testFont.canDisplay('a') && testFont.canDisplay('1')) {
                resultName = fontName;
            } else {
                resultName = currentFont.getName();
            }
        }
        return new Font(resultName, style >= 0 ? style : currentFont.getStyle(), size >= 0 ? size : currentFont.getSize());
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootPanel;
    }
}
