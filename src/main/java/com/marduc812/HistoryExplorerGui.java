package com.marduc812;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;

public class HistoryExplorerGui extends JPanel {

    private final JCheckBox twoHunCheckBox;
    private final JCheckBox threeHunCheckBox;
    private final JCheckBox fourHunCheckBox;
    private final JCheckBox fiveHunCheckBox;
    private final JCheckBox regExCheckBox;
    private final JCheckBox inScopeFilterBox;
    private final JCheckBox requestBox;
    private final JCheckBox responseBox;
    private final JTextField includeExtensionsinput;
    private final JTextField excludeExtensionsinput;
    private final JCheckBox showProtocolCheckBox;
    private final JCheckBox showPortCheckBox;
    private final DefaultTableModel tableModel;
    private final JButton searchBtn;
    private final JTextField searchInput;

    private  HistoryExplorer historyExplorer;

    public HistoryExplorerGui(MontoyaApi api) {

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        // BORDER VIEW
        Border roundedLineBorder = new javax.swing.border.LineBorder(Color.BLACK, 1, true);
        TitledBorder titledBorder = new TitledBorder(roundedLineBorder, "Search HTTP History");
        Border emptyBorder = new EmptyBorder(10, 10, 10, 10);
        Border compoundBorder = new CompoundBorder(titledBorder, emptyBorder);
        titledBorder.setTitleFont(titledBorder.getTitleFont().deriveFont(Font.BOLD));

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(compoundBorder);


        // MAIN SEARCH
        JPanel searchInputPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        searchInput = new JTextField("");
        searchBtn = new JButton("Search");

        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        int width = (int) (screenSize.width * 0.3); // 30% of screen width
        searchInput.setPreferredSize(new Dimension(width - 10, searchInput.getPreferredSize().height));
        searchInput.setBorder(BorderFactory.createCompoundBorder(
                searchInput.getBorder(),
                BorderFactory.createEmptyBorder(0, 5, 0, 5)
        ));

        searchBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if ("Search".equals(searchBtn.getText())) {
                    // Start the search
                    searchBtn.setText("Stop");
                    searchInput.setEnabled(false);

                    // Collect search parameters and start a new HistoryExplorer
                    String userInput = searchInput.getText();
                    boolean[] checkboxStates = getCheckboxStates();
                    boolean regExSearch = regExCheckBox.isSelected();
                    boolean inScopeSearch = inScopeFilterBox.isSelected();
                    boolean showProt = showProtocolCheckBox.isSelected();
                    boolean showPort = showPortCheckBox.isSelected();
                    boolean reqSearch = requestBox.isSelected();
                    boolean resSearch = responseBox.isSelected();
                    List<Boolean> httpOptions = new ArrayList<>();
                    httpOptions.add(reqSearch);
                    httpOptions.add(resSearch);
                    String includedExtensions = includeExtensionsinput.getText();
                    String excludeExtensions = excludeExtensionsinput.getText();

                    historyExplorer = new HistoryExplorer(api, HistoryExplorerGui.this, userInput, regExSearch, inScopeSearch, checkboxStates, showProt, showPort, includedExtensions, excludeExtensions, httpOptions);
                } else {
                    // Stop the search
                    // stopSearch() signals historyExplorer itself, so don't do it twice
                    stopSearch();
                }
            }
        });


        searchInputPanel.add(searchInput);
        searchInputPanel.add(searchBtn);


        // REGEX LAYOUT & SCOPE FILTER
        JPanel regexOptionsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        regExCheckBox = new JCheckBox("RegEx Search");
        inScopeFilterBox = new JCheckBox("Only In-Scope");

        regexOptionsPanel.add(regExCheckBox);
        regexOptionsPanel.add(inScopeFilterBox);


        // HTTP options FILTER
        JPanel httpOptionsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        JLabel filterHTTPLabel = new JLabel("Filter HTTP: ");
        requestBox = new JCheckBox("Requests");
        responseBox = new JCheckBox("Responses", true);

        httpOptionsPanel.add(filterHTTPLabel);
        httpOptionsPanel.add(requestBox);
        httpOptionsPanel.add(responseBox);

        // STATUS RESPONSE CODES LAYOUT
        JPanel searchOptionsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));

        JLabel optionsLabel = new JLabel("Status filter:");
        twoHunCheckBox = new JCheckBox("2XX", true);
        threeHunCheckBox = new JCheckBox("3XX", true);
        fourHunCheckBox = new JCheckBox("4XX", true);
        fiveHunCheckBox = new JCheckBox("5XX", true);


        searchOptionsPanel.add(optionsLabel);
        searchOptionsPanel.add(twoHunCheckBox);
        searchOptionsPanel.add(threeHunCheckBox);
        searchOptionsPanel.add(fourHunCheckBox);
        searchOptionsPanel.add(fiveHunCheckBox);

        // EXTENSION CODE LAYOUT
        JPanel searchExtensionPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));

        JLabel includeExtensionsLabel = new JLabel("Include extensions: ");
        JLabel excludeExtensionsLabel = new JLabel("Exclude extensions: ");


        includeExtensionsinput = new JTextField("");
        includeExtensionsinput.setPreferredSize(new Dimension(300,includeExtensionsinput.getPreferredSize().height));
        excludeExtensionsinput = new JTextField("");
        excludeExtensionsinput.setPreferredSize(new Dimension(300,excludeExtensionsinput.getPreferredSize().height));


        JButton helpBtn = new JButton("?");

        helpBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Parent the dialog on this tab. A dedicated JFrame was used here, but it
                // was never shown and carried EXIT_ON_CLOSE, which would have taken the
                // whole of Burp down with it.
                JOptionPane.showMessageDialog(HistoryExplorerGui.this, "Extensions should be comma separated values. If you want to include/exclude requests without extensions you can use the \"none\" keyword. ", "Help window", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        searchExtensionPanel.add(includeExtensionsLabel);
        searchExtensionPanel.add(includeExtensionsinput);
        searchExtensionPanel.add(excludeExtensionsLabel);
        searchExtensionPanel.add(excludeExtensionsinput);
        searchExtensionPanel.add(helpBtn);


        // Host column view layout
        JPanel hostColPrefsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));

        JLabel showProtocolLabel = new JLabel("Host filtering: ");

        showProtocolCheckBox = new JCheckBox("Protocol", true);
        showPortCheckBox = new JCheckBox("Port", true);

        hostColPrefsPanel.add(showProtocolLabel);
        hostColPrefsPanel.add(showProtocolCheckBox);
        hostColPrefsPanel.add(showPortCheckBox);

        // OUTPUT
        JPanel outputPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));

        String[] columnNames = {"Host", "Output"};

        Map<String, String> dataMap = new LinkedHashMap<>();

        String[][] data = new String[dataMap.size()][2];
        int index = 0;
        for (Map.Entry<String, String> entry : dataMap.entrySet()) {
            data[index][0] = entry.getKey();
            data[index][1] = entry.getValue();
            index++;
        }


        tableModel = new DefaultTableModel(data, columnNames);
        JTable table = new JTable(tableModel);

        int tableWidth = (int) (screenSize.width * 0.8);
        int tableHeight = (int) (screenSize.height * 0.5);

        // Add JTable to JScrollPane
        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setPreferredSize(new Dimension(tableWidth, tableHeight));
        outputPanel.add(scrollPane);

        // RESIZE THE VIEWS
        searchInputPanel.setMaximumSize(searchInputPanel.getPreferredSize());
        regexOptionsPanel.setMaximumSize(regexOptionsPanel.getPreferredSize());
        searchOptionsPanel.setMaximumSize(searchOptionsPanel.getPreferredSize());
        httpOptionsPanel.setMaximumSize(searchOptionsPanel.getPreferredSize());
        searchExtensionPanel.setMaximumSize(searchExtensionPanel.getPreferredSize());

        // ADD EVERY VIEW

        // Create the box layout
        mainPanel.add(searchInputPanel);
        mainPanel.add(regexOptionsPanel);
        mainPanel.add(httpOptionsPanel);
        mainPanel.add(searchOptionsPanel);
        mainPanel.add(hostColPrefsPanel);
        mainPanel.add(searchExtensionPanel);


        // Add every view
        add(mainPanel);
        add(outputPanel);
    }

    // Make the button available when not searching
    public void enableSearchButton() {
        java.awt.EventQueue.invokeLater(() -> {
            searchInput.setEnabled(true);
            // stopSearch() disables the button while it waits, so re-enable it here too
            // or a search that finishes mid-stop leaves it dead until the timer fires.
            searchBtn.setEnabled(true);
            searchBtn.setText("Search");
        });
    }

    public void stopSearch() {
        SwingUtilities.invokeLater(() -> {
            searchBtn.setEnabled(false);
            searchInput.setEnabled(false);
            searchBtn.setText("Stopping...");

            if (historyExplorer != null) {
                historyExplorer.stopSearch();
            }

            Timer timer = new Timer(2000, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SwingUtilities.invokeLater(() -> {
                        searchBtn.setEnabled(true);
                        searchBtn.setText("Search");
                        searchInput.setEnabled(true);
                    });
                }
            });
            timer.setRepeats(false);
            timer.start();
        });
    }




    private boolean[] getCheckboxStates() {
        return new boolean[]{
                twoHunCheckBox.isSelected(),
                threeHunCheckBox.isSelected(),
                fourHunCheckBox.isSelected(),
                fiveHunCheckBox.isSelected()
        };
    }

    public void updateTableData(Map<String, String> newData) {
        // Clear the existing data
        tableModel.setRowCount(0);

        // Add the new data
        for (Map.Entry<String, String> entry : newData.entrySet()) {
            tableModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
        }
    }
}
