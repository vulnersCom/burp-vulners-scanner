package burp.gui;

import burp.BurpExtender;
import burp.VulnersService;
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
    private JTextField tbxProxyHost;
    private JTextField tbxProxyPort;
    private JCheckBox cbxProxyEnabled;
    private JCheckBox cbxPathScanInScope;

    private RulesTable rulesTable;
    private PathsTable pathsTable;
    private SoftwareTable softwareTable;
    private final Map<String, Domain> domains;

    public TabComponent(final BurpExtender burpExtender, IBurpExtenderCallbacks callbacks, final Map<String, Domain> domains) {
        this.burpExtender = burpExtender;
        this.callbacks = callbacks;
        this.domains = domains;

        $$$setupUI$$$();

        /*
         * Rules Table and support Buttons
         */
        final RulesTableListener ruleTableListener = new RulesTableListener(callbacks, this.tblRules, this.rulesTable.getDefaultModel(), burpExtender);
        this.tblRules.getModel().addTableModelListener(ruleTableListener);

        btnRuleAdd.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent e) {
                new Thread(new Runnable() {
                    public void run() {
                        ruleTableListener.onAddButtonClick(e);
                    }
                }).start();
            }
        });

        btnRuleRemove.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent e) {
                new Thread(new Runnable() {
                    public void run() {
                        ruleTableListener.onRemoveButtonClick(e);
                    }
                }).start();
            }
        });

        btnRulesLoad.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent e) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        burpExtender.getVulnersService().loadRules();
                    }
                }).start();
            }
        });

        btnTblPathClear.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent e) {
                for (Map.Entry<String, Domain> d : domains.entrySet()) {
                    d.getValue().setPaths(new HashMap<String, Set<Vulnerability>>());
                }
                pathsTable.getDefaultModel().setRowCount(0);
            }
        });

        btnTblSoftwareClear.addActionListener(new ActionListener() {
            public void actionPerformed(final ActionEvent e) {
                for (Map.Entry<String, Domain> d : domains.entrySet()) {
                    d.getValue().setSoftware(new HashMap<String, Software>());
                }
                softwareTable.getDefaultModel().setRowCount(0);
            }
        });

        cbxSoftwareShowVuln.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                softwareTable.refreshTable(domains, cbxSoftwareShowVuln.isSelected());
            }
        });

        tbxProxyHost.addActionListener(getProxyChangeListener());
        tbxProxyPort.addActionListener(getProxyChangeListener());
        cbxProxyEnabled.addActionListener(getProxyChangeListener());
    }

    private ActionListener getProxyChangeListener() {
        return new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                boolean proxyEnabled = cbxProxyEnabled.isSelected();
                VulnersService.setProxy(
                        proxyEnabled ? tbxProxyHost.getText() : "",
                        proxyEnabled ? tbxProxyPort.getText() : ""
                );
            }
        };
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

    public Double getTbxReqLimitValue() {
        try {
            return Double.valueOf(tbxReqLimit.getText());
        } catch (Exception e) {
            return 4.0; // Magic number of rate limits
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
        rootPanel.setLayout(new GridLayoutManager(5, 19, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1 = new JTabbedPane();
        tabbedPane1.setTabPlacement(1);
        rootPanel.add(tabbedPane1, new GridConstraints(0, 0, 5, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_VERTICAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(4, 5, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Scan rules", panel1);
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(4, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new GridConstraints(0, 0, 1, 5, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel2.add(spacer1, new GridConstraints(2, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setFont(new Font(label1.getFont().getName(), Font.BOLD, 14));
        label1.setText("Software vulnerability scanner");
        panel2.add(label1, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Uses vulners.com API to detect vulnerabilities in flagged version of software.");
        panel2.add(label2, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setFont(new Font(label3.getFont().getName(), Font.BOLD, label3.getFont().getSize()));
        label3.setHorizontalAlignment(2);
        label3.setIcon(new ImageIcon(getClass().getResource("/logo_small.png")));
        label3.setText("");
        panel2.add(label3, new GridConstraints(1, 0, 3, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(-1, 60), new Dimension(-1, 60), 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Match rules use regular expressions to flag software version numbers in server responses. ");
        panel2.add(label4, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("Rules URL");
        panel1.add(label5, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtRulesURL = new JTextField();
        txtRulesURL.setText("https://vulners.com/api/v3/burp/rules");
        panel1.add(txtRulesURL, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        btnRulesLoad = new JButton();
        btnRulesLoad.setText("Load");
        panel1.add(btnRulesLoad, new GridConstraints(1, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, 1, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(51, 27), null, 0, false));
        scrlPanel = new JScrollPane();
        panel1.add(scrlPanel, new GridConstraints(2, 0, 1, 4, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        scrlPanel.setViewportView(tblRules);
        btnRuleAdd = new JButton();
        btnRuleAdd.setText("Add");
        panel1.add(btnRuleAdd, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnRuleRemove = new JButton();
        btnRuleRemove.setText("Remove");
        panel1.add(btnRuleRemove, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(8, 2, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Results", panel3);
        final JScrollPane scrollPane1 = new JScrollPane();
        panel3.add(scrollPane1, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(454, 126), null, 0, false));
        scrollPane1.setViewportView(tblSoftware);
        btnTblSoftwareClear = new JButton();
        btnTblSoftwareClear.setText("Clear");
        panel3.add(btnTblSoftwareClear, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setFont(new Font(label6.getFont().getName(), Font.BOLD, label6.getFont().getSize()));
        label6.setText("Vulnerable Software");
        panel3.add(label6, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel3.add(spacer2, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        cbxSoftwareShowVuln = new JCheckBox();
        cbxSoftwareShowVuln.setSelected(false);
        cbxSoftwareShowVuln.setText("Show only vulnerable software");
        panel3.add(cbxSoftwareShowVuln, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JSeparator separator1 = new JSeparator();
        panel3.add(separator1, new GridConstraints(4, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JLabel label7 = new JLabel();
        label7.setFont(new Font(label7.getFont().getName(), Font.BOLD, label7.getFont().getSize()));
        label7.setText("Possible vulnerable software uses specific paths");
        panel3.add(label7, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane2 = new JScrollPane();
        panel3.add(scrollPane2, new GridConstraints(6, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(454, 126), null, 0, false));
        scrollPane2.setViewportView(tblPaths);
        btnTblPathClear = new JButton();
        btnTblPathClear.setText("Clear");
        panel3.add(btnTblPathClear, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(9, 3, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Options", panel4);
        tbxReqLimit = new JTextField();
        tbxReqLimit.setText("4");
        panel4.add(tbxReqLimit, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label8 = new JLabel();
        label8.setText("Request per second");
        panel4.add(label8, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_EAST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label9 = new JLabel();
        label9.setFont(new Font(label9.getFont().getName(), Font.BOLD, label9.getFont().getSize()));
        label9.setText("Scan options");
        panel4.add(label9, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cbxPathSearch = new JCheckBox();
        cbxPathSearch.setEnabled(true);
        cbxPathSearch.setSelected(false);
        cbxPathSearch.setText("");
        panel4.add(cbxPathSearch, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(51, 20), null, 0, false));
        final JLabel label10 = new JLabel();
        label10.setText("Use scan by locations paths (Experimental)");
        panel4.add(label10, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label11 = new JLabel();
        label11.setFont(new Font(label11.getFont().getName(), Font.BOLD, label11.getFont().getSize()));
        label11.setText("ProxyOptions");
        panel4.add(label11, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label12 = new JLabel();
        label12.setText("Host");
        panel4.add(label12, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_EAST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer3 = new Spacer();
        panel4.add(spacer3, new GridConstraints(8, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        tbxProxyHost = new JTextField();
        tbxProxyHost.setText("127.0.0.1");
        panel4.add(tbxProxyHost, new GridConstraints(6, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final Spacer spacer4 = new Spacer();
        panel4.add(spacer4, new GridConstraints(6, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JLabel label13 = new JLabel();
        label13.setText("Port");
        panel4.add(label13, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_EAST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        tbxProxyPort = new JTextField();
        tbxProxyPort.setText("8888");
        panel4.add(tbxProxyPort, new GridConstraints(7, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label14 = new JLabel();
        label14.setText("Proxy enabled");
        panel4.add(label14, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_EAST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cbxProxyEnabled = new JCheckBox();
        cbxProxyEnabled.setText("");
        panel4.add(cbxProxyEnabled, new GridConstraints(5, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label15 = new JLabel();
        label15.setText("Scope Only");
        panel4.add(label15, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_EAST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cbxPathScanInScope = new JCheckBox();
        cbxPathScanInScope.setEnabled(true);
        cbxPathScanInScope.setSelected(true);
        cbxPathScanInScope.setText("");
        panel4.add(cbxPathScanInScope, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(51, 20), null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootPanel;
    }
}
