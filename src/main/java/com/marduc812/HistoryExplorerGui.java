package com.marduc812;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.IntSupplier;

public class HistoryExplorerGui extends JPanel {

    /**
     * Above this many result rows the tree stays collapsed after a search. Expanding
     * tens of thousands of nodes is slow and unreadable; the user can still hit
     * "Expand all" or filter first.
     */
    private static final int AUTO_EXPAND_LIMIT = 1000;

    /**
     * FlowLayout that reports the height it will actually occupy once it has wrapped.
     * Stock FlowLayout always measures as a single row, so a BoxLayout parent gives it
     * one row's worth of height and clips everything that wrapped below.
     */
    private static class WrapLayout extends FlowLayout {

        /**
         * The width the container is about to be given, which during a resize is not
         * yet the width it has: parents ask a child for its preferred height before
         * they assign its bounds. Measuring against the stale width picks the wrong
         * number of rows and clips the last one until something revalidates.
         */
        private final IntSupplier widthHint;

        WrapLayout(int hgap, int vgap, IntSupplier widthHint) {
            super(LEFT, hgap, vgap);
            this.widthHint = widthHint;
        }

        @Override
        public Dimension preferredLayoutSize(Container target) {
            return layoutSize(target, true);
        }

        @Override
        public Dimension minimumLayoutSize(Container target) {
            Dimension size = layoutSize(target, false);
            size.width -= getHgap() + 1;
            return size;
        }

        private Dimension layoutSize(Container target, boolean preferred) {
            synchronized (target.getTreeLock()) {

                int targetWidth = widthHint == null ? 0 : widthHint.getAsInt();
                if (targetWidth <= 0) {
                    targetWidth = target.getSize().width;
                }
                if (targetWidth <= 0) {
                    // Not laid out yet: measure as one row, as FlowLayout would.
                    targetWidth = Integer.MAX_VALUE;
                }

                Insets insets = target.getInsets();
                int horizontalInsetsAndGap = insets.left + insets.right + getHgap() * 2;
                int maxWidth = targetWidth - horizontalInsetsAndGap;

                Dimension size = new Dimension(0, 0);
                int rowWidth = 0;
                int rowHeight = 0;

                for (Component member : target.getComponents()) {

                    if (!member.isVisible()) {
                        continue;
                    }

                    Dimension memberSize = preferred ? member.getPreferredSize() : member.getMinimumSize();

                    if (rowWidth + memberSize.width > maxWidth && rowWidth != 0) {
                        addRow(size, rowWidth, rowHeight);
                        rowWidth = 0;
                        rowHeight = 0;
                    }

                    if (rowWidth != 0) {
                        rowWidth += getHgap();
                    }

                    rowWidth += memberSize.width;
                    rowHeight = Math.max(rowHeight, memberSize.height);
                }

                addRow(size, rowWidth, rowHeight);

                size.width += horizontalInsetsAndGap;
                size.height += insets.top + insets.bottom + getVgap() * 2;
                return size;
            }
        }

        private void addRow(Dimension size, int rowWidth, int rowHeight) {
            size.width = Math.max(size.width, rowWidth);
            if (size.height > 0) {
                size.height += getVgap();
            }
            size.height += rowHeight;
        }
    }

    /**
     * Stand-in row for an empty tree. A type rather than a marker string, so a host
     * whose name happens to match the message is still rendered as a host.
     */
    private static class Placeholder {

        private final String text;

        Placeholder(String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

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
    private final JButton searchBtn;
    private final JTextField searchInput;

    private final JTree resultTree;
    private final DefaultMutableTreeNode resultRoot;
    private final DefaultTreeModel resultModel;
    private final JTextField resultFilterInput;
    private final JLabel resultSummaryLabel;
    private final JProgressBar searchProgress;

    /** The last full result set, kept so the result filter can re-derive the tree. */
    private Map<String, List<String>> results = new LinkedHashMap<>();

    private HistoryExplorer historyExplorer;

    public HistoryExplorerGui(MontoyaApi api) {

        Font displayFont = api.userInterface().currentDisplayFont();
        Font valueFont = api.userInterface().currentEditorFont();

        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // MAIN SEARCH
        searchInput = new JTextField();
        searchInput.putClientProperty("JTextField.placeholderText", "Search the proxy history...");
        searchBtn = new JButton("Search");
        searchBtn.setPreferredSize(new Dimension(110, searchBtn.getPreferredSize().height));

        searchProgress = new JProgressBar();
        searchProgress.setIndeterminate(true);
        searchProgress.setVisible(false);
        searchProgress.setPreferredSize(new Dimension(0, 3));

        searchBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if ("Search".equals(searchBtn.getText())) {
                    // Start the search
                    searchBtn.setText("Stop");
                    searchInput.setEnabled(false);
                    searchProgress.setVisible(true);
                    resultSummaryLabel.setText("Searching...");

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

        // Enter in the search field is the same as pressing the button.
        searchInput.addActionListener(e -> searchBtn.doClick());

        JPanel searchInputPanel = new JPanel(new BorderLayout(8, 0));
        searchInputPanel.add(searchInput, BorderLayout.CENTER);
        searchInputPanel.add(searchBtn, BorderLayout.EAST);

        // MATCHING OPTIONS
        regExCheckBox = new JCheckBox("Regular expression");
        inScopeFilterBox = new JCheckBox("In-scope only");
        requestBox = new JCheckBox("Requests");
        responseBox = new JCheckBox("Responses", true);

        // STATUS CODES AND HOST COLUMN
        twoHunCheckBox = new JCheckBox("2XX", true);
        threeHunCheckBox = new JCheckBox("3XX", true);
        fourHunCheckBox = new JCheckBox("4XX", true);
        fiveHunCheckBox = new JCheckBox("5XX", true);
        showProtocolCheckBox = new JCheckBox("Protocol", true);
        showPortCheckBox = new JCheckBox("Port", true);

        // EXTENSIONS
        includeExtensionsinput = new JTextField(14);
        excludeExtensionsinput = new JTextField(14);

        String extensionHelp = "Comma separated, e.g. js, json. Use \"none\" for paths with no extension.";
        includeExtensionsinput.setToolTipText(extensionHelp);
        excludeExtensionsinput.setToolTipText(extensionHelp);

        JButton helpBtn = new JButton("?");
        helpBtn.setToolTipText("How extension filtering works");
        helpBtn.setMargin(new Insets(0, 6, 0, 6));

        helpBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Parent the dialog on this tab. A dedicated JFrame was used here, but it
                // was never shown and carried EXIT_ON_CLOSE, which would have taken the
                // whole of Burp down with it.
                JOptionPane.showMessageDialog(HistoryExplorerGui.this, "Extensions should be comma separated values. If you want to include/exclude requests without extensions you can use the \"none\" keyword. ", "Help window", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // Every option lives in a titled group. Flat, they were three undifferentiated
        // rows of ten checkboxes with no clue which one affected what.
        // The option row spans the tab, so the width it will get is the tab's width
        // less this panel's border. The tab is the outermost component and is resized
        // first, which makes that hint current on the very first layout pass.
        IntSupplier optionsWidth = () -> getWidth() - getInsets().left - getInsets().right;

        JPanel optionsPanel = new JPanel(new WrapLayout(10, 4, optionsWidth)) {
            @Override
            public Dimension getMaximumSize() {
                // Recomputed rather than fixed once, because the preferred height
                // changes as WrapLayout reflows the groups.
                return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
            }
        };

        optionsPanel.add(group("Search in", displayFont, requestBox, responseBox));
        optionsPanel.add(group("Matching", displayFont, regExCheckBox, inScopeFilterBox));
        optionsPanel.add(group("Status codes", displayFont, twoHunCheckBox, threeHunCheckBox, fourHunCheckBox, fiveHunCheckBox));
        optionsPanel.add(group("Show in host", displayFont, showProtocolCheckBox, showPortCheckBox));
        optionsPanel.add(group("Extensions", displayFont, label("Include", displayFont), includeExtensionsinput,
                null, label("Exclude", displayFont), excludeExtensionsinput, helpBtn));

        // WrapLayout's preferred height depends on the width it is given, so the
        // enclosing BoxLayout has to be asked to measure again after a resize.
        optionsPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                optionsPanel.revalidate();
            }
        });

        JPanel controlsPanel = new JPanel();
        controlsPanel.setLayout(new BoxLayout(controlsPanel, BoxLayout.Y_AXIS));
        controlsPanel.setBorder(new EmptyBorder(0, 0, 10, 0));
        controlsPanel.add(searchInputPanel);
        controlsPanel.add(Box.createVerticalStrut(8));
        controlsPanel.add(optionsPanel);
        controlsPanel.add(Box.createVerticalStrut(6));
        controlsPanel.add(searchProgress);

        // Keep the fixed-height rows from stretching when the tab is tall.
        for (Component fixed : new Component[]{searchInputPanel, searchProgress}) {
            ((JComponent) fixed).setMaximumSize(new Dimension(Integer.MAX_VALUE, fixed.getPreferredSize().height));
        }
        for (Component child : new Component[]{searchInputPanel, optionsPanel, searchProgress}) {
            ((JComponent) child).setAlignmentX(LEFT_ALIGNMENT);
        }

        // RESULTS
        resultRoot = new DefaultMutableTreeNode("Results");
        resultModel = new DefaultTreeModel(resultRoot);
        resultTree = new JTree(resultModel);
        resultTree.setRootVisible(false);
        resultTree.setShowsRootHandles(true);
        resultTree.setRowHeight(0); // let the renderer decide, so the value font fits
        resultTree.getSelectionModel().setSelectionMode(TreeSelectionModel.DISCONTIGUOUS_TREE_SELECTION);
        resultTree.setCellRenderer(new ResultRenderer(displayFont, valueFont));
        resultTree.setToolTipText("");

        installCopyActions();

        resultFilterInput = new JTextField(20);
        resultFilterInput.setToolTipText("Narrow the results below. Matches hosts and values.");
        resultFilterInput.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                rebuildTree();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                rebuildTree();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                rebuildTree();
            }
        });

        resultSummaryLabel = label("No results yet", displayFont);

        JButton expandBtn = new JButton("Expand all");
        JButton collapseBtn = new JButton("Collapse all");
        expandBtn.addActionListener(e -> setAllExpanded(true));
        collapseBtn.addActionListener(e -> setAllExpanded(false));

        JPanel resultToolbar = new JPanel(new BorderLayout(8, 0));
        JPanel resultToolbarLeft = row(label("Filter results:", displayFont), resultFilterInput,
                null, resultSummaryLabel);

        JPanel resultToolbarRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        resultToolbarRight.add(expandBtn);
        resultToolbarRight.add(collapseBtn);

        resultToolbar.add(resultToolbarLeft, BorderLayout.WEST);
        resultToolbar.add(resultToolbarRight, BorderLayout.EAST);
        resultToolbar.setBorder(new EmptyBorder(8, 0, 6, 0));

        JPanel resultHeader = new JPanel(new BorderLayout());
        resultHeader.add(new JSeparator(), BorderLayout.NORTH);
        resultHeader.add(resultToolbar, BorderLayout.CENTER);

        JPanel resultPanel = new JPanel(new BorderLayout());
        resultPanel.add(resultHeader, BorderLayout.NORTH);
        resultPanel.add(new JScrollPane(resultTree), BorderLayout.CENTER);

        add(controlsPanel, BorderLayout.NORTH);
        add(resultPanel, BorderLayout.CENTER);

        api.userInterface().applyThemeToComponent(this);
    }

    /**
     * A left-aligned row of controls, 6px apart, with a null marking a wider break
     * between groups. The layout gap is 0 so the first item lines up with the search
     * field and the results below rather than sitting one gap to the right.
     */
    private static JPanel row(Component... items) {

        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 3));
        boolean startOfGroup = true;

        for (Component item : items) {
            if (item == null) {
                panel.add(Box.createHorizontalStrut(20));
                startOfGroup = true;
                continue;
            }
            if (!startOfGroup) {
                panel.add(Box.createHorizontalStrut(6));
            }
            panel.add(item);
            startOfGroup = false;
        }

        return panel;
    }

    /** A {@link #row} of controls under a titled border, so each option says what it governs. */
    private static JPanel group(String title, Font font, Component... items) {

        JPanel panel = row(items);
        TitledBorder border = BorderFactory.createTitledBorder(title);

        if (font != null) {
            border.setTitleFont(font.deriveFont(font.getSize2D() - 1f));
        }

        panel.setBorder(new CompoundBorder(border, new EmptyBorder(0, 5, 3, 5)));
        return panel;
    }

    private static JLabel label(String text, Font font) {
        JLabel label = new JLabel(text);
        if (font != null) {
            label.setFont(font);
        }
        return label;
    }

    // Make the button available when not searching
    public void enableSearchButton() {
        java.awt.EventQueue.invokeLater(() -> {
            searchInput.setEnabled(true);
            // stopSearch() disables the button while it waits, so re-enable it here too
            // or a search that finishes mid-stop leaves it dead until the timer fires.
            searchBtn.setEnabled(true);
            searchBtn.setText("Search");
            searchProgress.setVisible(false);
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
                        searchProgress.setVisible(false);
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

    /**
     * Hands a finished search to the tree. Keys are hosts, values are that host's
     * distinct matches, both already sorted by the search engine.
     */
    public void updateResults(Map<String, List<String>> newData) {
        results = newData;
        rebuildTree();
    }

    /** Rebuilds the tree from {@link #results}, applying the result filter. */
    private void rebuildTree() {

        String filter = resultFilterInput.getText().trim().toLowerCase(Locale.ROOT);
        resultRoot.removeAllChildren();

        int hostCount = 0;
        int valueCount = 0;

        for (Map.Entry<String, List<String>> entry : results.entrySet()) {

            String host = entry.getKey();
            boolean hostMatches = filter.isEmpty() || host.toLowerCase(Locale.ROOT).contains(filter);

            // A host whose own name matches keeps all its values; otherwise it keeps
            // only the values that match, and drops out entirely if none do.
            List<String> shown = new ArrayList<>();
            for (String value : entry.getValue()) {
                if (hostMatches || value.toLowerCase(Locale.ROOT).contains(filter)) {
                    shown.add(value);
                }
            }

            if (shown.isEmpty()) {
                continue;
            }

            DefaultMutableTreeNode hostNode = new DefaultMutableTreeNode(host);
            for (String value : shown) {
                hostNode.add(new DefaultMutableTreeNode(value));
            }
            resultRoot.add(hostNode);

            hostCount++;
            valueCount += shown.size();
        }

        if (hostCount == 0) {
            String message = results.isEmpty()
                    ? "Nothing to show yet. Enter a search term above and press Search."
                    : "No host or value matches this filter.";
            resultRoot.add(new DefaultMutableTreeNode(new Placeholder(message)));
        }

        resultModel.reload();

        if (results.isEmpty()) {
            resultSummaryLabel.setText("No results");
        } else {
            resultSummaryLabel.setText(hostCount + (hostCount == 1 ? " host, " : " hosts, ") + valueCount + (valueCount == 1 ? " value" : " values"));
        }

        if (valueCount > 0 && valueCount <= AUTO_EXPAND_LIMIT) {
            setAllExpanded(true);
        }
    }

    private void setAllExpanded(boolean expanded) {
        for (int i = 0; i < resultRoot.getChildCount(); i++) {
            TreePath path = new TreePath(new Object[]{resultRoot, resultRoot.getChildAt(i)});
            if (expanded) {
                resultTree.expandPath(path);
            } else {
                resultTree.collapsePath(path);
            }
        }
    }

    /** Ctrl/Cmd+C and a right-click menu, since a tree has no copy behaviour of its own. */
    private void installCopyActions() {

        Action copySelection = new AbstractAction("Copy") {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyToClipboard(selectionAsText());
            }
        };

        Action copyAll = new AbstractAction("Copy all results") {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyToClipboard(allAsText());
            }
        };

        int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        resultTree.getInputMap(WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_C, menuMask), "copySelection");
        resultTree.getActionMap().put("copySelection", copySelection);

        JPopupMenu menu = new JPopupMenu();
        menu.add(copySelection);
        menu.add(copyAll);

        resultTree.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showMenu(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showMenu(e);
            }

            private void showMenu(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                // Right-clicking a row the user has not selected should act on that row.
                TreePath path = resultTree.getPathForLocation(e.getX(), e.getY());
                if (path != null && !resultTree.isPathSelected(path)) {
                    resultTree.setSelectionPath(path);
                }
                menu.show(resultTree, e.getX(), e.getY());
            }
        });
    }

    private String selectionAsText() {

        TreePath[] paths = resultTree.getSelectionPaths();
        if (paths == null) {
            return "";
        }

        StringBuilder text = new StringBuilder();
        for (TreePath path : paths) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            if (node.getUserObject() instanceof Placeholder) {
                continue;
            }
            if (node.isLeaf() && node.getParent() != resultRoot) {
                // A value: prefix it with its host so a copied selection stays meaningful.
                text.append(node.getParent()).append('\t').append(node).append('\n');
            } else {
                text.append(node).append('\n');
            }
        }
        return text.toString();
    }

    private String allAsText() {

        StringBuilder text = new StringBuilder();
        for (int i = 0; i < resultRoot.getChildCount(); i++) {
            DefaultMutableTreeNode hostNode = (DefaultMutableTreeNode) resultRoot.getChildAt(i);
            for (int j = 0; j < hostNode.getChildCount(); j++) {
                text.append(hostNode).append('\t').append(hostNode.getChildAt(j)).append('\n');
            }
        }
        return text.toString();
    }

    private static void copyToClipboard(String text) {
        if (!text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        }
    }

    /**
     * Hosts in bold with their match count, values in the editor font. The default
     * renderer's folder and leaf icons are dropped; they read as a file browser,
     * which this is not.
     */
    private static class ResultRenderer extends DefaultTreeCellRenderer {

        private final Font hostFont;
        private final Font valueFont;

        ResultRenderer(Font displayFont, Font valueFont) {
            this.hostFont = displayFont == null ? null : displayFont.deriveFont(Font.BOLD);
            this.valueFont = valueFont;
            setLeafIcon(null);
            setOpenIcon(null);
            setClosedIcon(null);
        }

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {

            super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);

            DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;

            if (node.getUserObject() instanceof Placeholder) {
                if (hostFont != null) {
                    setFont(hostFont.deriveFont(Font.ITALIC));
                }
                setToolTipText(null);
                return this;
            }

            if (node.getLevel() == 1) {
                setText(node.getUserObject() + "  (" + node.getChildCount() + ")");
                if (hostFont != null) {
                    setFont(hostFont);
                }
            } else if (valueFont != null) {
                setFont(valueFont);
            }

            // The full value, for matches too wide for the panel.
            setToolTipText(String.valueOf(node.getUserObject()));

            return this;
        }
    }
}
