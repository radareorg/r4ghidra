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
import java.util.Arrays;
import java.util.ArrayList;
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
     * Get the REPL context for configuration access
     * 
     * @return The current R2Context instance
     */
    public r4ghidra.repl.R2Context getREPLContext() {
        return repl != null ? repl.getContext() : null;
    }

    /**
     * Bring the component to the front and ensure it's visible
     * This method will create a dialog window if needed
     */
    public void toFront() {
        // Show this provider as a dockable component in the Ghidra tool
        getTool().showComponentProvider(this, true);
    }

    private JPanel mainPanel;
    // Font to use for shell UI
    private Font shellFont;
    private JTextArea outputArea;
    private JTextField commandField;
    private JButton executeButton;
    private R2REPLImpl repl;
    private ArrayList<String> commandHistory;
    private int historyIndex = -1;

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
        // Determine font: prefer STMono, fallback to monospaced
        String desiredFont = "ST Mono";
        boolean hasDesired = Arrays.asList(
            GraphicsEnvironment.getLocalGraphicsEnvironment()
                .getAvailableFontFamilyNames()
        ).contains(desiredFont);
        String fontName = hasDesired ? desiredFont : Font.MONOSPACED;
        // shellFont = new Font(fontName, Font.PLAIN, 12);
        shellFont = new Font(Font.MONOSPACED, Font.BOLD, 12);

        repl = new R2REPLImpl();
        commandHistory = new ArrayList<>();
        
        // Register the shell provider with the REPL context for font updates
        repl.getContext().setShellProvider(this);

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
                        // Special case for 'x' command alias
                        // If the help text contains "x[j]" pattern, it's our x alias
                        if (help.contains("x[j]")) {
                            commandRegistry.put("x", handler);
                        } else {
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
        outputArea.setFont(shellFont);
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
        commandField.setFont(shellFont);

        // Handle Enter key and up/down keys in the command field
        commandField.addKeyListener(
            new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                        executeCommand();
                    } else if (e.getKeyCode() == KeyEvent.VK_UP || (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_P)) {
                        // Up arrow or Ctrl+P: Show previous command
                        showPreviousCommand();
                    } else if (e.getKeyCode() == KeyEvent.VK_DOWN || (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_N)) {
                        // Down arrow or Ctrl+N: Show next command
                        showNextCommand();
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
        // Scroll output to bottom
        outputArea.setCaretPosition(outputArea.getDocument().getLength());

        // Add the command to history if it's not empty and not a duplicate of the last command
        if (!command.isEmpty()) {
            if (commandHistory.isEmpty() || !command.equals(commandHistory.get(commandHistory.size() - 1))) {
                commandHistory.add(command);
            }
            historyIndex = commandHistory.size();
        }
        
        // Clear the command field
        commandField.setText("");

        // Request focus back to command field
        commandField.requestFocusInWindow();
    }
    
    /**
     * Update the font used in the console
     * 
     * @param newFont The new font to use
     */
    public void updateFont(Font newFont) {
        if (newFont == null) {
            return;
        }
        
        this.shellFont = newFont;
        
        // Update the font on the UI components
        if (outputArea != null) {
            outputArea.setFont(newFont);
        }
        
        if (commandField != null) {
            commandField.setFont(newFont);
        }
    }
    
    /**
     * Clear the output text area
     * This method is called by the clear command handler
     */
    public void clearOutputArea() {
        if (outputArea != null) {
            outputArea.setText("");
        }
    }
    
    /**
     * Show the previous command in the history
     */
    private void showPreviousCommand() {
        if (commandHistory.isEmpty()) {
            return;
        }
        
        // If we're at the end of the history, save the current text
        if (historyIndex == commandHistory.size()) {
            String currentText = commandField.getText().trim();
            if (!currentText.isEmpty()) {
                // Temporarily store the current unexecuted text
                commandHistory.add(currentText);
                // But we'll remove it once we execute a command or leave the field
            }
        }
        
        if (historyIndex > 0) {
            historyIndex--;
            commandField.setText(commandHistory.get(historyIndex));
            // Position cursor at end of text
            commandField.setCaretPosition(commandField.getText().length());
        }
    }
    
    /**
     * Show the next command in the history
     */
    private void showNextCommand() {
        if (commandHistory.isEmpty() || historyIndex >= commandHistory.size() - 1) {
            // At the end of history, clear the field
            if (historyIndex == commandHistory.size() - 1) {
                historyIndex = commandHistory.size();
                commandField.setText("");
            }
            return;
        }
        
        historyIndex++;
        commandField.setText(commandHistory.get(historyIndex));
        // Position cursor at end of text
        commandField.setCaretPosition(commandField.getText().length());
    }
    
    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}
