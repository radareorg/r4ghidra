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

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import java.awt.BorderLayout;
import java.awt.Frame;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import javax.swing.SwingUtilities;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.handlers.*;
import r4ghidra.repl.handlers.R2ClearCommandHandler;
import r4ghidra.repl.handlers.R2FlagCommandHandler;
import r4ghidra.repl.handlers.R2QuitCommandHandler;

/** Provide class-level documentation that describes what this plugin does. */
// @formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName =
        CorePluginPackage.NAME, // https://github.com/NationalSecurityAgency/ghidra/discussions/5175
    category = PluginCategoryNames.EXAMPLES,
    shortDescription = "R4Ghidra - Radare2/Ghidra Integration",
    description = "R4Ghidra provides integration between Ghidra and Radare2.")
// @formatter:on
public class R4GhidraPlugin extends ProgramPlugin {

  MyProvider provider;
  R4CommandShellProvider shellProvider;
  private List<R2CommandHandler> commandHandlers;
  private boolean shellProviderAdded = false;

  /**
   * Plugin constructor.
   *
   * @param tool The plugin tool that this plugin is added to.
   */
  public R4GhidraPlugin(PluginTool tool) {
    super(tool);

    // Customize provider (or remove if a provider is not desired)
    String pluginName = getName();
    provider = new MyProvider(this, pluginName);

    // Customize help (or remove if help is not desired)
    String topicName = this.getClass().getPackage().getName();
    String anchorName = "HelpAnchor";
    provider.setHelpLocation(new HelpLocation(topicName, anchorName));

    // Initialize command handlers list
    commandHandlers = new ArrayList<>();
  }

  @Override
  public void init() {
    super.init();
    // Initialize command handlers
    initCommandHandlers();
    // Create and register UI actions now that the tool is initialized
    if (provider != null) {
      provider.createActions();
    }
  }

  /** Initialize all command handlers for R4Ghidra */
  private void initCommandHandlers() {
    // Register all command handlers
    commandHandlers.add(new R2SeekCommandHandler());
    commandHandlers.add(new R2PrintCommandHandler());
    // Register the print command handler again with 'x' prefix as an alias for 'px'
    commandHandlers.add(
        new R2PrintCommandHandler() {
          @Override
          public String execute(r4ghidra.repl.R2Command command, r4ghidra.repl.R2Context context)
              throws r4ghidra.repl.R2CommandException {
            // Modify the command to prefix with 'p' to make it look like 'px'
            r4ghidra.repl.R2Command modifiedCommand =
                new r4ghidra.repl.R2Command(
                    "p", // Change prefix to 'p'
                    "x" + command.getSubcommand(), // Prefix subcommand with 'x'
                    command.getArguments(), // Keep original arguments
                    command.getTemporaryAddress() // Keep original temporary address
                    );
            // Execute the modified command through the regular handler
            return super.execute(modifiedCommand, context);
          }

          @Override
          public String getHelp() {
            // Return a modified help string that includes the 'x' command
            StringBuilder help = new StringBuilder();
            help.append("Usage: x[j] [count]\n");
            help.append(" x [len]      print hexdump (alias for px)\n");
            help.append(" xj [len]     print hexdump as json (alias for pxj)\n");
            help.append("\nExamples:\n");
            help.append(" x            print hexdump using default block size\n");
            help.append(" x 32         print 32 bytes hexdump\n");
            help.append(" xj 16        print 16 bytes hexdump as json\n");
            return help.toString();
          }
        });
    commandHandlers.add(new R2BlocksizeCommandHandler());
    // commandHandlers.add(new R2DecompileCommandHandler());
    commandHandlers.add(new R2EnvCommandHandler());
    commandHandlers.add(new R2EvalCommandHandler());
    commandHandlers.add(new R2ShellCommandHandler());
    // Analyze commands: af, afl, afi
    commandHandlers.add(new R2AnalyzeCommandHandler());
    commandHandlers.add(new R2InfoCommandHandler());
    commandHandlers.add(new R2CommentCommandHandler());
    commandHandlers.add(new R2FlagCommandHandler());
    commandHandlers.add(new R2QuitCommandHandler());
    commandHandlers.add(new R2ClearCommandHandler());

    // Note: R2HelpCommandHandler will be created in the CommandShellProvider
    // because it needs a reference to the command registry

    // Add more handlers as needed
  }

  /**
   * Get the registered command handlers
   *
   * @return List of command handlers
   */
  public List<R2CommandHandler> getCommandHandlers() {
    return commandHandlers;
  }

  @Override
  protected void programOpened(Program program) {
    R4GhidraState.api = new FlatProgramAPI(program);

    // Set initial seek to the current cursor position in the UI
    R4GhidraState.r2Seek = getCurrentAddressFromUI(program);

    // Create the command shell when a program is opened
    if (shellProvider == null) {
      shellProvider = new R4CommandShellProvider(this, "R4Ghidra Shell");
    }
  }

  /**
   * Get the current address from the UI cursor position Falls back to program entry point, or image
   * base if entry point is not available
   */
  private Address getCurrentAddressFromUI(Program program) {
    // Try to get the current cursor position from the tool
    try {
      Object currentLocation =
          getTool()
              .getService(ghidra.app.services.GoToService.class)
              .getDefaultNavigatable()
              .getLocation();
      if (currentLocation != null
          && currentLocation instanceof ghidra.program.util.ProgramLocation) {
        return ((ghidra.program.util.ProgramLocation) currentLocation).getAddress();
      }
    } catch (Exception e) {
      // Fall through to other methods if this fails
    }

    // Try to get the program entry point
    try {
      if (program.getExecutablePath() != null) {
        Address entryPoint = program.getImageBase();
        if (entryPoint != null) {
          return entryPoint;
        }
      }
    } catch (Exception e) {
      // Fall through to using image base
    }

    // Fall back to program image base
    return program.getImageBase();
  }

  @Override
  protected void programClosed(Program program) {
    // Dispose the command shell when program is closed
    if (shellProvider != null) {
      shellProvider.close();
      shellProvider = null;
    }
  }

  private static class MyProvider extends ComponentProvider {
    // Reference to the owning plugin (cast from PluginTool)
    private final R4GhidraPlugin plugin;

    private JPanel panel;
    private DockingAction startAction;
    private DockingAction stopAction;
    private DockingAction commandShellAction;
    private DockingAction settingsAction;

    /** Update enabled state of start/stop actions based on server status. */
    private void updateStartStopActions() {
      boolean running = R4GhidraServer.isRunning();
      startAction.setEnabled(!running);
      stopAction.setEnabled(running);
    }

    public MyProvider(Plugin plugin, String owner) {
      super(plugin.getTool(), owner, owner);
      // Store reference to the owning plugin
      this.plugin = (R4GhidraPlugin) plugin;
      // Actions will be created in plugin.init(), ensuring the tool menu is ready
    }

    /** Shows the R4Ghidra command shell */
    private void showCommandShell() {
      if (plugin != null) {
        try {
          // Instantiate the shell provider if needed
          if (plugin.shellProvider == null) {
            plugin.shellProvider = new R4CommandShellProvider(plugin, "R4Ghidra Shell");
          }
          // Show the command shell as a dockable component in the tool
          if (!plugin.shellProviderAdded) {
            // Add the shell provider to the tool (not shown initially)
            plugin.getTool().addComponentProvider(plugin.shellProvider, false);
            plugin.shellProviderAdded = true;
          }
          plugin.getTool().showComponentProvider(plugin.shellProvider, true);
        } catch (Exception e) {
          System.err.println("Error showing R4Ghidra command shell: " + e.getMessage());
          e.printStackTrace();
          OkDialog.showError("R4Ghidra Error", "Error opening command shell: " + e.getMessage());
        }
      }
    }

    // Customize actions
    public void createActions() {
      startAction =
          new DockingAction("R4Ghidra Start Action", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
              try {
                String strPort =
                    OptionDialog.showInputSingleLineDialog(
                        null, "R4Ghidra", "Server port:", "9191");
                Integer intPort = Integer.parseInt(strPort);
                R4GhidraServer.start(intPort.intValue());
                OkDialog.showInfo(
                    "R4Ghidra",
                    "R4Ghidra server started on port "
                        + strPort
                        + ".\n\nGet the best of both worlds!");
                // Update menu entries
                MyProvider.this.updateStartStopActions();
              } catch (IOException ioe) {
                OkDialog.showError("R4Ghidra Error", ioe.getMessage());
              }
            }
          };

      startAction.setMenuBarData(
          new MenuData(
              new String[] { // Menu Path
                ToolConstants.MENU_TOOLS, "R4Ghidra", "Start R4Ghidra server..."
              },
              null, // Icon
              "r4ghidra", // Menu Group
              MenuData.NO_MNEMONIC, // Mnemonic
              "1" // Menu Subgroup
              ));

      stopAction =
          new DockingAction("R4Ghidra Stop Action", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
              R4GhidraServer.stop();
              OkDialog.showInfo("R4Ghidra", "R4Ghidra server stopped.");
              // Update menu entries
              MyProvider.this.updateStartStopActions();
            }
          };

      stopAction.setMenuBarData(
          new MenuData(
              new String[] { // Menu Path
                ToolConstants.MENU_TOOLS, "R4Ghidra", "Stop R4Ghidra server"
              },
              null, // Icon
              "r4ghidra", // Menu Group
              MenuData.NO_MNEMONIC, // Mnemonic
              "1" // Menu Subgroup
              ));
      // Create the command shell action
      commandShellAction =
          new DockingAction("R4Ghidra Command Shell Action", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
              showCommandShell();
            }
          };

      commandShellAction.setMenuBarData(
          new MenuData(
              new String[] { // Menu Path
                ToolConstants.MENU_TOOLS, "R4Ghidra", "Open Command Shell"
              },
              null, // Icon
              "r4ghidra", // Menu Group
              MenuData.NO_MNEMONIC, // Mnemonic
              "1" // Menu Subgroup
              ));

      // action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
      // Configure action enablement based on server state
      startAction.markHelpUnnecessary();
      stopAction.markHelpUnnecessary();
      commandShellAction.markHelpUnnecessary();
      dockingTool.addAction(startAction);
      dockingTool.addAction(stopAction);
      // Update start/stop enablement
      updateStartStopActions();
      dockingTool.addAction(commandShellAction);
      // Action to open settings dialog
      settingsAction =
          new DockingAction("R4Ghidra Settings", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
              showSettingsDialog();
            }
          };
      settingsAction.setMenuBarData(
          new MenuData(
              new String[] {ToolConstants.MENU_TOOLS, "R4Ghidra", "Settings..."},
              null,
              "r4ghidra",
              MenuData.NO_MNEMONIC,
              "2"));
      settingsAction.setEnabled(true);
      settingsAction.markHelpUnnecessary();
      dockingTool.addAction(settingsAction);
    }

    @Override
    public JComponent getComponent() {
      return panel;
    }

    /** Shows the settings dialog for R4Ghidra. */
    private void showSettingsDialog() {
      PluginTool pluginTool = (PluginTool) dockingTool;
      Frame owner = pluginTool.getToolFrame();
      SwingUtilities.invokeLater(
          () -> {
            createAndShowSettingsDialog(owner);
          });
    }

    /**
     * Creates and displays the settings dialog with server status indicator and configuration
     * variable grid.
     */
    private void createAndShowSettingsDialog(Frame owner) {
      JDialog dialog = new JDialog(owner, "R4Ghidra Settings", true);
      dialog.setSize(600, 400);
      dialog.getContentPane().setLayout(new BorderLayout(10, 10));

      // Create main panel with some padding
      JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
      mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

      // Server status panel at the top
      JPanel statusPanel = createServerStatusPanel();
      mainPanel.add(statusPanel, BorderLayout.NORTH);

      // Config variables panel in the center
      JPanel configPanel = createConfigVariablesPanel();
      mainPanel.add(configPanel, BorderLayout.CENTER);

      // Button panel at the bottom
      JPanel buttonPanel = new JPanel();
      JButton closeButton = new JButton("Close");
      closeButton.addActionListener(e -> dialog.dispose());
      buttonPanel.add(closeButton);
      mainPanel.add(buttonPanel, BorderLayout.SOUTH);

      dialog.getContentPane().add(mainPanel);
      dialog.setLocationRelativeTo(owner);
      dialog.setVisible(true);
    }

    /** Creates a panel showing the server status. */
    private JPanel createServerStatusPanel() {
      JPanel panel = new JPanel(new BorderLayout(5, 0));
      panel.setBorder(BorderFactory.createTitledBorder("Server Status"));

      boolean isRunning = R4GhidraServer.isRunning();
      String statusText = isRunning ? "RUNNING" : "STOPPED";
      JLabel statusLabel = new JLabel("Server status: " + statusText);
      statusLabel.setForeground(isRunning ? new java.awt.Color(0, 128, 0) : java.awt.Color.RED);
      statusLabel.setFont(statusLabel.getFont().deriveFont(java.awt.Font.BOLD));

      JPanel statusInfoPanel = new JPanel(new BorderLayout());
      statusInfoPanel.add(statusLabel, BorderLayout.WEST);

      if (isRunning) {
        JButton stopButton = new JButton("Stop Server");
        stopButton.addActionListener(
            e -> {
              R4GhidraServer.stop();
              updateStartStopActions();
              // Recreate and show the dialog to refresh
              ((JDialog) panel.getTopLevelAncestor()).dispose();
              createAndShowSettingsDialog(((PluginTool) dockingTool).getToolFrame());
            });
        statusInfoPanel.add(stopButton, BorderLayout.EAST);
      } else {
        JButton startButton = new JButton("Start Server");
        startButton.addActionListener(
            e -> {
              try {
                String strPort =
                    OptionDialog.showInputSingleLineDialog(
                        null, "R4Ghidra", "Server port:", "9191");
                if (strPort != null && !strPort.isEmpty()) {
                  Integer intPort = Integer.parseInt(strPort);
                  R4GhidraServer.start(intPort.intValue());
                  updateStartStopActions();
                  // Recreate and show the dialog to refresh
                  ((JDialog) panel.getTopLevelAncestor()).dispose();
                  createAndShowSettingsDialog(((PluginTool) dockingTool).getToolFrame());
                }
              } catch (IOException ioe) {
                OkDialog.showError("R4Ghidra Error", ioe.getMessage());
              } catch (NumberFormatException nfe) {
                OkDialog.showError("R4Ghidra Error", "Invalid port number");
              }
            });
        statusInfoPanel.add(startButton, BorderLayout.EAST);
      }

      panel.add(statusInfoPanel, BorderLayout.CENTER);
      return panel;
    }

    /** Creates a panel with a grid of configuration variables. */
    private JPanel createConfigVariablesPanel() {
      JPanel panel = new JPanel(new BorderLayout());
      panel.setBorder(BorderFactory.createTitledBorder("Configuration Variables"));

      // Get the current R2 REPL context to access configuration variables
      r4ghidra.repl.R2Context r2Context = null;
      if (plugin.shellProvider != null) {
        r2Context = plugin.shellProvider.getREPLContext();
      }

      if (r2Context == null) {
        // No context available yet, show a message
        panel.add(
            new JLabel("Open the Command Shell first to view configuration variables."),
            BorderLayout.CENTER);
        return panel;
      }

      // Get configuration variables from the context
      r4ghidra.repl.config.R2EvalConfig evalConfig = r2Context.getEvalConfig();
      java.util.Map<String, String> configVars = evalConfig.getAll();

      // Create table model for the grid
      ConfigVariableTableModel tableModel = new ConfigVariableTableModel(configVars, evalConfig);

      // Create the table with the model
      JTable configTable = new JTable(tableModel);
      configTable.setRowHeight(25);
      configTable.getColumnModel().getColumn(0).setPreferredWidth(150);
      configTable.getColumnModel().getColumn(1).setPreferredWidth(250);

      // Set custom cell editor for the value column
      configTable.getColumnModel().getColumn(1).setCellEditor(new ConfigValueCellEditor());

      // Add the table to a scroll pane
      JScrollPane scrollPane = new JScrollPane(configTable);
      panel.add(scrollPane, BorderLayout.CENTER);

      return panel;
    }

    /** Table model for configuration variables. */
    private class ConfigVariableTableModel extends javax.swing.table.AbstractTableModel {
      private java.util.List<String> keys = new java.util.ArrayList<>();
      private java.util.List<String> values = new java.util.ArrayList<>();
      private r4ghidra.repl.config.R2EvalConfig evalConfig;

      public ConfigVariableTableModel(
          java.util.Map<String, String> configVars, r4ghidra.repl.config.R2EvalConfig evalConfig) {
        this.evalConfig = evalConfig;

        // Convert the map to sorted lists for table display
        java.util.List<String> sortedKeys = new java.util.ArrayList<>(configVars.keySet());
        java.util.Collections.sort(sortedKeys);

        for (String key : sortedKeys) {
          keys.add(key);
          values.add(configVars.get(key));
        }
      }

      @Override
      public int getRowCount() {
        return keys.size();
      }

      @Override
      public int getColumnCount() {
        return 2;
      }

      @Override
      public String getColumnName(int column) {
        return column == 0 ? "Name" : "Value";
      }

      @Override
      public Object getValueAt(int rowIndex, int columnIndex) {
        if (columnIndex == 0) {
          return keys.get(rowIndex);
        } else {
          return values.get(rowIndex);
        }
      }

      @Override
      public boolean isCellEditable(int rowIndex, int columnIndex) {
        // Only the value column is editable
        return columnIndex == 1;
      }

      @Override
      public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 1 && aValue != null) {
          String key = keys.get(rowIndex);
          String newValue = aValue.toString();

          // Update the value in the config
          evalConfig.set(key, newValue);

          // Update the local cache
          values.set(rowIndex, newValue);

          // Notify listeners that the value has changed
          fireTableCellUpdated(rowIndex, columnIndex);
        }
      }
    }

    /** Custom cell editor for configuration variable values. */
    private class ConfigValueCellEditor extends javax.swing.DefaultCellEditor {
      public ConfigValueCellEditor() {
        super(new JTextField());
      }

      @Override
      public java.awt.Component getTableCellEditorComponent(
          JTable table, Object value, boolean isSelected, int row, int column) {
        // Get the key name to determine the type of editor to use
        String key = (String) table.getValueAt(row, 0);
        String strValue = value != null ? value.toString() : "";

        if (isBooleanKey(key)) {
          // For boolean values, use a combo box
          JComboBox<String> comboBox = new JComboBox<>(new String[] {"true", "false"});
          comboBox.setSelectedItem(strValue);
          return comboBox;
        } else if (isNumericKey(key)) {
          // For numeric values, use a text field with input verification
          JTextField textField =
              (JTextField) super.getTableCellEditorComponent(table, value, isSelected, row, column);
          textField.setInputVerifier(
              new javax.swing.InputVerifier() {
                @Override
                public boolean verify(javax.swing.JComponent input) {
                  try {
                    String text = ((JTextField) input).getText();
                    Integer.parseInt(text);
                    return true;
                  } catch (NumberFormatException e) {
                    return false;
                  }
                }
              });
          return textField;
        } else {
          // For string values, use a regular text field
          return super.getTableCellEditorComponent(table, value, isSelected, row, column);
        }
      }

      @Override
      public Object getCellEditorValue() {
        java.awt.Component editor = getComponent();
        if (editor instanceof JComboBox) {
          return ((JComboBox<?>) editor).getSelectedItem();
        } else {
          return super.getCellEditorValue();
        }
      }

      private boolean isBooleanKey(String key) {
        // Determine if a key represents a boolean value
        return key.equals("scr.prompt")
            || key.equals("cfg.bigendian")
            || key.equals("io.cache")
            || key.equals("cfg.sandbox")
            || key.equals("scr.follow")
            || key.toLowerCase().contains(".enable")
            || key.toLowerCase().contains(".enabled")
            || key.toLowerCase().endsWith(".on")
            || key.toLowerCase().endsWith(".off");
      }

      private boolean isNumericKey(String key) {
        // Determine if a key represents a numeric value
        return key.equals("scr.fontsize")
            || key.equals("asm.bits")
            || key.equals("asm.bytes")
            || key.equals("http.port")
            || key.toLowerCase().endsWith(".size")
            || key.toLowerCase().contains(".width")
            || key.toLowerCase().contains(".height")
            || key.toLowerCase().contains(".count");
      }
    }
  }
}
