/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package r4ghidra;

import docking.ComponentProvider;
import ghidra.util.HelpLocation;
import java.awt.*;
import java.awt.event.*;
import java.util.HashMap;
import java.util.Map;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.DefaultCaret;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2REPLImpl;
import r4ghidra.repl.handlers.R2HelpCommandHandler;

/**
 * Command shell provider for R4Ghidra.
 * Provides a UI for interacting with the R4Ghidra command system directly.
 */
public class R4CommandShellProvider extends ComponentProvider {

    // Flag to track if dialog has been shown
    private boolean isDialogShown = false;

    // Make this method public for plugin access
    public void close() {
        getTool().removeComponentProvider(this);
    }

    /**
     * Bring the component to the front and ensure it's visible
     * This method will create a dialog window if needed
     */
    public void toFront() {
        try {
            JComponent comp = getComponent();
            if (comp != null) {
                Window win = SwingUtilities.getWindowAncestor(comp);
                if (win == null || !win.isVisible()) {
                    // If no window ancestor or not visible, create a floating dialog
                    if (!isDialogShown) {
                        JDialog dialog = new JDialog();
                            // null, // SwingUtilities.getWindowAncestor(getTool().getActiveWindow()),
                            // "R4Ghidra Command Shell");
                        dialog.setSize(600, 400);
                        // dialog.setLocationRelativeTo(getTool().getActiveWindow());
                        dialog.setContentPane(comp);
                        dialog.setDefaultCloseOperation(
                            JDialog.DISPOSE_ON_CLOSE
                        );
                        dialog.addWindowListener(
                            new WindowAdapter() {
                                @Override
                                public void windowClosed(WindowEvent e) {
                                    isDialogShown = false;
                                }
                            }
                        );
                        dialog.setVisible(true);
                        isDialogShown = true;
                    }
                } else {
                    win.toFront();
                }
            }
        } catch (Exception e) {
            System.err.println(
                "Error bringing R4Ghidra console to front: " + e.getMessage()
            );
            e.printStackTrace();
            // Show error in GUI dialog
            docking.widgets.OkDialog.showError(
                "R4Ghidra Error",
                "Error opening command shell: " + e.getMessage()
            );
        }
    }

    private JPanel mainPanel;
    private JTextArea outputArea;
    private JTextField commandField;
    private JButton executeButton;
    private R2REPLImpl repl;

    /**
     * Constructor
     *
     * @param plugin The R4GhidraPlugin that owns this provider
     * @param title The title of the component
     */
    public R4CommandShellProvider(R4GhidraPlugin plugin, String title) {
        super(plugin.getTool(), title, title);
        // Add this provider to the Window menu
        setWindowMenuGroup("R4Ghidra");

        repl = new R2REPLImpl();

        // Register all command handlers from the plugin
        Map<String, R2CommandHandler> commandRegistry = new HashMap<>();
        for (R2CommandHandler handler : plugin.getCommandHandlers()) {
            // For the special case of R2HelpCommandHandler, we need to register it with the commandRegistry
            if (
                handler instanceof r4ghidra.repl.handlers.R2HelpCommandHandler
            ) {
                // We'll add it at the end after populating the registry
            } else {
                // Get the prefix from the command's first character in its help text
                String help = handler.getHelp();
                if (help != null && !help.isEmpty()) {
                    // Extract the command prefix from the first line (usually "Usage: prefix...")
                    String firstLine = help.split("\\n")[0];
                    String prefix = "";
                    if (firstLine.contains("Usage:")) {
                        String[] parts = firstLine.split("\\s+");
                        for (String part : parts) {
                            if (part.length() > 0 && !part.equals("Usage:")) {
                                // Get the first character of the command as the prefix
                                prefix = part.substring(0, 1);
                                break;
                            }
                        }
                    }

                    if (!prefix.isEmpty()) {
                        commandRegistry.put(prefix, handler);
                    }
                }
            }
        }

        // Now add the help command handler with the registry
        R2CommandHandler helpHandler = new R2HelpCommandHandler(
            commandRegistry
        );
        commandRegistry.put("?", helpHandler);

        // Register all commands with the REPL
        for (Map.Entry<
            String,
            R2CommandHandler
        > entry : commandRegistry.entrySet()) {
            repl.registerCommand(entry.getKey(), entry.getValue());
        }

        buildPanel();
        setHelpLocation(new HelpLocation("R4Ghidra", "CommandShell"));
    }

    /**
     * Builds the UI panel with output area and command input field
     */
    private void buildPanel() {
        mainPanel = new JPanel(new BorderLayout(0, 5));
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Create the output area (top row)
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setBackground(Color.BLACK);
        outputArea.setForeground(Color.WHITE);
        outputArea.setText(
            "R4Ghidra Command Shell\nType commands and press Enter to execute.\n\n"
        );

        // Auto-scroll to bottom for new content
        DefaultCaret caret = (DefaultCaret) outputArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);

        // Add scrollbars to the output area
        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setVerticalScrollBarPolicy(
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS
        );
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Create the command input panel (bottom row)
        JPanel commandPanel = new JPanel(new BorderLayout(5, 0));

        // Command input field
        commandField = new JTextField();
        commandField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        // Handle Enter key in the command field
        commandField.addKeyListener(
            new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                        executeCommand();
                    }
                }
            }
        );

        // Execute button
        executeButton = new JButton("Execute");
        executeButton.addActionListener(e -> executeCommand());

        // Add components to the command panel
        commandPanel.add(commandField, BorderLayout.CENTER);
        commandPanel.add(executeButton, BorderLayout.EAST);

        // Add the command panel to the main panel
        mainPanel.add(commandPanel, BorderLayout.SOUTH);
    }

    /**
     * Execute the command in the command field
     */
    private void executeCommand() {
        String command = commandField.getText().trim();
        if (command.isEmpty()) {
            return;
        }

        // Add the command to the output area
        outputArea.append("> " + command + "\n");

        // Execute the command
        String result = repl.executeCommand(command);

        // Display the result
        outputArea.append(result + "\n");

        // Clear the command field
        commandField.setText("");

        // Request focus back to command field
        commandField.requestFocusInWindow();
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}
