package r4ghidra.repl;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.util.*;

import r4ghidra.R4CommandShellProvider;
import r4ghidra.repl.config.R2EvalChangeListener;
import r4ghidra.repl.config.R2EvalConfig;
import r4ghidra.repl.filesystem.R2FileSystem;
import r4ghidra.repl.filesystem.R2SandboxedFileSystem;
import r4ghidra.R4GhidraState;

/**
 * Context for R2 command execution
 *
 * <p>This class encapsulates all state needed during command execution, including: - Current
 * address (seek) - Block size - Program API - Command output capture - Error handling -
 * User-defined variables
 */
public class R2Context {
  // Sandbox permission flags
  /** No sandbox restrictions */
  public static final int R_SANDBOX_GRAIN_NONE = 0;
  /** Restrict socket operations */
  public static final int R_SANDBOX_GRAIN_SOCKET = 1;
  /** Restrict disk access operations */
  public static final int R_SANDBOX_GRAIN_DISK = 2;
  /** Restrict file operations */
  public static final int R_SANDBOX_GRAIN_FILES = 4;
  /** Restrict command execution */
  public static final int R_SANDBOX_GRAIN_EXEC = 8;
  /** Restrict environment variable access */
  public static final int R_SANDBOX_GRAIN_ENVIRON = 16;
  /** Apply all sandbox restrictions */
  public static final int R_SANDBOX_GRAIN_ALL = 16 | 8 | 4 | 2 | 1;


  // Current address (seek)
  private Address currentAddress;
  private Stack<Address> addressUndoStack;
  private Stack<Address> addressRedoStack;

  // Block size for commands that read/write blocks of memory
  private int blockSize;

  // Last command error code
  private int lastErrorCode;

  // Last error message
  private String lastErrorMessage;

  // User-defined variables
  private Map<String, String> variables;

  // Configuration manager
  private R2EvalConfig evalConfig;

  // Sandbox permissions
  private int sandboxFlags;

  // File system abstraction
  private R2FileSystem fileSystem;

  // Flag storage (maps flag names to addresses)
  private Map<String, Long> flags;

  // Flag sizes (maps flag names to their sizes)
  private Map<String, Integer> flagSizes;

  // Current flagspace
  private String currentFlagspace;

  // Reference to the command shell provider for UI updates
  private R4CommandShellProvider shellProvider;

  /** Create a new context with default values */
  public R2Context() {
    // We'll initialize these from R4GhidraState for compatibility

    this.currentAddress = R4GhidraState.api.getCurrentProgram().getMinAddress();
    this.addressUndoStack =new Stack<Address>();
    this.addressRedoStack = new Stack<Address>();

    this.blockSize = 128;

    this.lastErrorCode = 0;
    this.lastErrorMessage = "";
    this.variables = new HashMap<>();

    // Initialize flag storage
    this.flags = new TreeMap<>();
    this.flagSizes = new HashMap<>();
    this.currentFlagspace = "*";

    // Initialize the eval config
    this.evalConfig = new R2EvalConfig(this);

    // Set up default listeners
    setupConfigListeners();

    // Lock the configuration to prevent creation of new keys by users
    // Only plugins and extensions should be able to create new keys
    this.evalConfig.lock();

    // By default, enable all sandbox restrictions
    this.sandboxFlags = R_SANDBOX_GRAIN_ALL;

    // Initialize the file system with sandbox restrictions
    this.fileSystem = new R2SandboxedFileSystem(this);
  }

  /** Create a new context with specified sandbox restrictions */
  public R2Context(int sandboxFlags) {
    this();
    this.sandboxFlags = sandboxFlags;
    this.fileSystem = new R2SandboxedFileSystem(this);
  }

  /** Set up listeners for configuration variables */
  private void setupConfigListeners() {
    // Listen for asm.bits changes
    evalConfig.registerListener(
        "asm.bits",
        new R2EvalChangeListener() {
          @Override
          public void onChange(String key, String oldValue, String newValue) {
            // Nothing to do for now, but in a real implementation
            // this would update the disassembler's bit mode
          }
        });

    // Listen for block size changes
    evalConfig.registerListener(
        "asm.bytes",
        new R2EvalChangeListener() {
          @Override
          public void onChange(String key, String oldValue, String newValue) {
            try {
              int newSize = Integer.parseInt(newValue);
              setBlockSize(newSize);
            } catch (NumberFormatException e) {
              // Ignore invalid values
            }
          }
        });

    // Listen for endian changes
    evalConfig.registerListener(
        "cfg.bigendian",
        new R2EvalChangeListener() {
          @Override
          public void onChange(String key, String oldValue, String newValue) {
            // Synchronize with cfg.endian
            if (newValue.equals("true") || newValue.equals("1")) {
              evalConfig.set("cfg.endian", "big", false); // Avoid circular updates
            } else {
              evalConfig.set("cfg.endian", "little", false); // Avoid circular updates
            }
          }
        });

    // Listen for endian changes (alternate syntax)
    evalConfig.registerListener(
        "cfg.endian",
        new R2EvalChangeListener() {
          @Override
          public void onChange(String key, String oldValue, String newValue) {
            // Synchronize with cfg.bigendian
            if (newValue.equalsIgnoreCase("big")) {
              evalConfig.set("cfg.bigendian", "true", false); // Avoid circular updates
            } else {
              evalConfig.set("cfg.bigendian", "false", false); // Avoid circular updates
            }
          }
        });

    // Listen for font name changes
    evalConfig.registerListener(
        "scr.font",
        new R2EvalChangeListener() {
          @Override
          public void onChange(String key, String oldValue, String newValue) {
            updateConsoleFont();
          }
        });

    // Listen for font size changes
    evalConfig.registerListener(
        "scr.fontsize",
        new R2EvalChangeListener() {
          @Override
          public void onChange(String key, String oldValue, String newValue) {
            updateConsoleFont();
          }
        });
  }

  /**
   * Get the current address (seek)
   * 
   * @return The current address, or null if not set
   */
  public Address getCurrentAddress() {
    return currentAddress;
  }

  /**
   * Set the current address (seek)
   * 
   * @param addr The address to set as current
   */
  public void setCurrentAddress(Address addr) {
    // Bail out in case of location event handler spam
    if (addr.equals(this.currentAddress)) return;

    Address prevAddress = this.currentAddress;
    this.currentAddress = addr;

    // Handling spam from location event handler
    this.addressUndoStack.push(prevAddress);
  }

  /**
   * Undoes the current address (seek)
   */
  public void undoCurrentAddress() {
    try {
      Address prevAddress = this.currentAddress; // We shouldn't push if there's nothing to pop!
      this.currentAddress = this.addressUndoStack.pop();
      this.addressRedoStack.push(prevAddress);
    }catch(EmptyStackException ese){
      // We just ignore the undo
    }
  }
   /**
   * Redoes the current address (seek)
   */
  public void redoCurrentAddress() {
    try {
      Address prevAddress = this.currentAddress; // We shouldn't push if there's nothing to pop!
      this.currentAddress = this.addressRedoStack.pop();
      this.addressUndoStack.push(prevAddress);
    }catch(EmptyStackException ese){
      // We just ignore the redo
    }
  }
  /**
   * Get the current block size
   * 
   * @return The current block size in bytes
   */
  public int getBlockSize() {
    return blockSize;
  }

  /**
   * Set the current block size
   * 
   * @param size The block size in bytes to set
   */
  public void setBlockSize(int size) {
    this.blockSize = size;

    // Update config value to stay in sync
    evalConfig.set("asm.bytes", Integer.toString(size), false); // Avoid circular updates
  }

  /**
   * Get the Ghidra API reference
   * 
   * @return The FlatProgramAPI instance
   */
  public FlatProgramAPI getAPI() {
    return R4GhidraState.api;
  }

  /**
   * Parse an address string into an Address object
   * 
   * @param addressStr The address string to parse
   * @return The Address object representing the parsed address
   */
  public Address parseAddress(String addressStr) {
    try {
      // Use R2NumUtil to evaluate complex expressions
      long addrValue = r4ghidra.repl.num.R2NumUtil.evaluateExpression(this, addressStr);
      return R4GhidraState.api.toAddr(addrValue);
    } catch (r4ghidra.repl.num.R2NumException e) {
      // Fall back to direct conversion if expression evaluation fails
      return R4GhidraState.api.toAddr(addressStr);
    }
  }

  /**
   * Format an address as a hex string
   * 
   * @param addr The address to format
   * @return The formatted address as a hex string
   */
  public String formatAddress(Address addr) {
    return "0x" + String.format("%1$08x", addr.getUnsignedOffset());
  }

  /**
   * Format a long value as a hex address string
   * 
   * @param addr The address value to format
   * @return The formatted address as a hex string
   */
  public String formatAddress(long addr) {
    return "0x" + String.format("%1$08x", addr);
  }

  /**
   * Set an error status
   * 
   * @param code The error code
   * @param message The error message
   */
  public void setError(int code, String message) {
    this.lastErrorCode = code;
    this.lastErrorMessage = message;
  }

  /**
   * Get the last error code
   * 
   * @return The last error code, 0 if no error
   */
  public int getLastErrorCode() {
    return lastErrorCode;
  }

  /**
   * Get the last error message
   * 
   * @return The last error message, empty string if no error
   */
  public String getLastErrorMessage() {
    return lastErrorMessage;
  }

  /** Clear the error status */
  public void clearError() {
    this.lastErrorCode = 0;
    this.lastErrorMessage = "";
  }

  /**
   * Set a user-defined variable
   * 
   * @param name The variable name
   * @param value The variable value
   */
  public void setVariable(String name, String value) {
    variables.put(name, value);
  }

  /**
   * Get a user-defined variable
   * 
   * @param name The variable name
   * @return The variable value, or empty string if not defined
   */
  public String getVariable(String name) {
    return variables.getOrDefault(name, "");
  }

  /**
   * Check if a variable exists
   * 
   * @param name The variable name to check
   * @return True if the variable exists, false otherwise
   */
  public boolean hasVariable(String name) {
    return variables.containsKey(name);
  }

  /**
   * Get the configuration manager
   * 
   * @return The R2EvalConfig instance
   */
  public R2EvalConfig getEvalConfig() {
    return evalConfig;
  }

  /**
   * Get the current sandbox flags
   * 
   * @return The sandbox flags as a bitmask
   */
  public int getSandboxFlags() {
    return sandboxFlags;
  }

  /**
   * Set the sandbox flags
   * 
   * @param flags The sandbox flags as a bitmask
   */
  public void setSandboxFlags(int flags) {
    this.sandboxFlags = flags;
  }

  /**
   * Check if a specific sandbox restriction is enabled
   *
   * @param flag The flag to check
   * @return true if the restriction is enabled, false otherwise
   */
  public boolean isSandboxed(int flag) {
    return (sandboxFlags & flag) != 0;
  }

  /**
   * Get the file system abstraction
   * 
   * @return The R2FileSystem instance
   */
  public R2FileSystem getFileSystem() {
    return fileSystem;
  }

  /**
   * Set the command shell provider for UI updates
   *
   * @param provider The shell provider to use
   */
  public void setShellProvider(R4CommandShellProvider provider) {
    this.shellProvider = provider;
  }

  /**
   * Get the command shell provider
   *
   * @return The shell provider, or null if none is set
   */
  public R4CommandShellProvider getShellProvider() {
    return shellProvider;
  }

  /** Update the console font based on current eval settings */
  public void updateConsoleFont() {
    if (shellProvider == null) {
      return; // No UI to update
    }

    // Get font settings from config
    String fontName = getEvalConfig().get("scr.font");
    int fontSize = getEvalConfig().getInt("scr.fontsize");

    // Get all available fonts
    String[] availableFonts =
        GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames();

    // Check if the font exists
    boolean hasFont = Arrays.asList(availableFonts).contains(fontName);

    if (fontName.equals("?")) {
      showAvailableFontsDialog(availableFonts);
      return;
    }
    // Show font selection dialog if font doesn't exist
    if (!hasFont || fontName.equals("")) {
      // Use monospaced as fallback
      fontName = Font.MONOSPACED;
    }

    // Create the new font
    Font newFont = new Font(fontName, Font.BOLD, fontSize);

    // Apply the font to the UI
    shellProvider.updateFont(newFont);
  }

  /**
   * Show a dialog with available font family names
   *
   * @param availableFonts Array of available font family names
   */
  private void showAvailableFontsDialog(String[] availableFonts) {
    // Create a frame for the dialog
    javax.swing.JFrame frame = shellProvider.getToolFrame();

    // Create a list model with the font names
    javax.swing.DefaultListModel<String> listModel = new javax.swing.DefaultListModel<>();
    for (String fontName : availableFonts) {
      listModel.addElement(fontName);
    }

    // Create a list with the model
    javax.swing.JList<String> fontList = new javax.swing.JList<>(listModel);
    fontList.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

    // Add the list to a scroll pane
    javax.swing.JScrollPane scrollPane = new javax.swing.JScrollPane(fontList);
    scrollPane.setPreferredSize(new java.awt.Dimension(300, 400));

    // Create a panel for the buttons
    javax.swing.JPanel buttonPanel = new javax.swing.JPanel();
    javax.swing.JButton selectButton = new javax.swing.JButton("Select Font");
    javax.swing.JButton cancelButton = new javax.swing.JButton("Cancel");
    buttonPanel.add(selectButton);
    buttonPanel.add(cancelButton);

    // Create a panel for the dialog content
    javax.swing.JPanel dialogPanel = new javax.swing.JPanel(new java.awt.BorderLayout());
    dialogPanel.add(
        new javax.swing.JLabel("Available Font Families:"), java.awt.BorderLayout.NORTH);
    dialogPanel.add(scrollPane, java.awt.BorderLayout.CENTER);
    dialogPanel.add(buttonPanel, java.awt.BorderLayout.SOUTH);

    // Create the dialog
    javax.swing.JDialog dialog = new javax.swing.JDialog(frame, "Font Selection", true);
    dialog.setContentPane(dialogPanel);
    dialog.pack();
    dialog.setLocationRelativeTo(frame);

    // Add action listeners to buttons
    selectButton.addActionListener(
        e -> {
          String selectedFont = fontList.getSelectedValue();
          if (selectedFont != null) {
            // Update the font configuration
            getEvalConfig().set("scr.font", selectedFont);
          }
          dialog.dispose();
        });

    cancelButton.addActionListener(
        e -> {
          dialog.dispose();
        });

    // Show the dialog
    dialog.setVisible(true);
  }

  /**
   * Set a flag at the specified address
   *
   * @param name The name of the flag
   * @param address The address to set the flag at
   * @return true if the flag was set successfully, false otherwise
   */
  public boolean setFlag(String name, long address) {
    return setFlag(name, address, 1); // Default size is 1 byte
  }

  /**
   * Set a flag at the specified address with a specific size
   *
   * @param name The name of the flag
   * @param address The address to set the flag at
   * @param size The size of the flag in bytes
   * @return true if the flag was set successfully, false otherwise
   */
  public boolean setFlag(String name, long address, int size) {
    if (name == null || name.isEmpty() || size <= 0) {
      return false;
    }

    String formattedName = formatFlagName(name);
    // Store the flag and its size
    flags.put(formattedName, address);
    flagSizes.put(formattedName, size);
    return true;
  }

  /**
   * Set a flag at the current address
   *
   * @param name The name of the flag
   * @return true if the flag was set successfully, false otherwise
   */
  public boolean setFlag(String name) {
    if (currentAddress == null) {
      return false;
    }
    return setFlag(name, currentAddress.getOffset());
  }

  /**
   * Get the address of a flag by name
   *
   * @param name The name of the flag
   * @return The address of the flag, or null if the flag does not exist
   */
  public Long getFlagAddress(String name) {
    return flags.get(formatFlagName(name));
  }

  /**
   * Delete a flag by name
   *
   * @param name The name of the flag to delete
   * @return true if the flag was deleted, false if it didn't exist
   */
  public boolean deleteFlag(String name) {
    String formattedName = formatFlagName(name);
    if (flags.containsKey(formattedName)) {
      flags.remove(formattedName);
      flagSizes.remove(formattedName); // Also remove the size information
      return true;
    }
    return false;
  }

  /**
   * Get all flags
   *
   * @return A map of flag names to addresses
   */
  public Map<String, Long> getFlags() {
    return new HashMap<>(flags);
  }

  /**
   * Get the size of a flag
   *
   * @param name The name of the flag
   * @return The size of the flag in bytes, or 1 if not explicitly set
   */
  public int getFlagSize(String name) {
    String formattedName = formatFlagName(name);
    return flagSizes.getOrDefault(formattedName, 1); // Default size is 1 byte
  }

  /**
   * Get all flag sizes
   *
   * @return A map of flag names to sizes
   */
  public Map<String, Integer> getFlagSizes() {
    return new HashMap<>(flagSizes);
  }

  /**
   * Format a flag name to ensure it's valid
   *
   * @param name The raw flag name
   * @return A formatted flag name safe for use
   */
  private String formatFlagName(String name) {
    // If the flag contains a dot (indicating a flagspace)
    if (name.contains(".")) {
      return name; // Return as is - already includes flagspace
    } else if (!currentFlagspace.equals("*")) {
      // Prepend current flagspace
      return currentFlagspace + "." + name;
    }
    return name;
  }

  /**
   * Set the current flagspace
   *
   * @param flagspace The new flagspace to use
   */
  public void setFlagspace(String flagspace) {
    this.currentFlagspace = flagspace;
  }

  /**
   * Get the current flagspace
   *
   * @return The current flagspace
   */
  public String getCurrentFlagspace() {
    return currentFlagspace;
  }

  /**
   * Get all flagspaces currently in use
   *
   * @return A list of all flagspaces that have flags
   */
  public String[] getFlagspaces() {
    // Extract unique flagspaces from flag names
    java.util.Set<String> spaces = new java.util.HashSet<>();
    for (String flagName : flags.keySet()) {
      int dotIndex = flagName.indexOf('.');
      if (dotIndex > 0) {
        spaces.add(flagName.substring(0, dotIndex));
      }
    }
    return spaces.toArray(new String[0]);
  }
}
