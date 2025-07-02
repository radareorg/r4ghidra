package r4ghidra.repl;

import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import r4ghidra.R4CommandShellProvider;
import r4ghidra.R4GhidraState;
import r4ghidra.repl.config.R2EvalConfig;
import r4ghidra.repl.config.R2EvalChangeListener;
import r4ghidra.repl.filesystem.R2FileSystem;
import r4ghidra.repl.filesystem.R2SandboxedFileSystem;

/**
 * Context for R2 command execution
 * 
 * This class encapsulates all state needed during command execution, including:
 * - Current address (seek)
 * - Block size
 * - Program API
 * - Command output capture
 * - Error handling
 * - User-defined variables
 */
public class R2Context {
    // Sandbox permission flags
    public static final int R_SANDBOX_GRAIN_NONE = 0;
    public static final int R_SANDBOX_GRAIN_SOCKET = 1;
    public static final int R_SANDBOX_GRAIN_DISK = 2;
    public static final int R_SANDBOX_GRAIN_FILES = 4;
    public static final int R_SANDBOX_GRAIN_EXEC = 8;
    public static final int R_SANDBOX_GRAIN_ENVIRON = 16;
    public static final int R_SANDBOX_GRAIN_ALL = 16|8|4|2|1;
    
    // Ghidra API reference
    private FlatProgramAPI api;
    
    // Current address (seek)
    private Address currentAddress;
    
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
    
    // Reference to the command shell provider for UI updates
    private R4CommandShellProvider shellProvider;

    /**
     * Create a new context with default values
     */
    public R2Context() {
        // We'll initialize these from R4GhidraState for compatibility
        this.api = R4GhidraState.api;
        this.currentAddress = R4GhidraState.r2Seek;
        this.blockSize = R4GhidraState.blockSize;
        
        this.lastErrorCode = 0;
        this.lastErrorMessage = "";
        this.variables = new HashMap<>();
        
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
    
    /**
     * Create a new context with specified sandbox restrictions
     */
    public R2Context(int sandboxFlags) {
        this();
        this.sandboxFlags = sandboxFlags;
        this.fileSystem = new R2SandboxedFileSystem(this);
    }
    
    /**
     * Set up listeners for configuration variables
     */
    private void setupConfigListeners() {
        // Listen for asm.bits changes
        evalConfig.registerListener("asm.bits", new R2EvalChangeListener() {
            @Override
            public void onChange(String key, String oldValue, String newValue) {
                // Nothing to do for now, but in a real implementation
                // this would update the disassembler's bit mode
            }
        });
        
        // Listen for block size changes
        evalConfig.registerListener("asm.bytes", new R2EvalChangeListener() {
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
        evalConfig.registerListener("cfg.bigendian", new R2EvalChangeListener() {
            @Override
            public void onChange(String key, String oldValue, String newValue) {
                // Synchronize with cfg.endian
                if (newValue.equals("true") || newValue.equals("1")) {
                    evalConfig.set("cfg.endian", "big", false);  // Avoid circular updates
                } else {
                    evalConfig.set("cfg.endian", "little", false);  // Avoid circular updates
                }
            }
        });
        
        // Listen for endian changes (alternate syntax)
        evalConfig.registerListener("cfg.endian", new R2EvalChangeListener() {
            @Override
            public void onChange(String key, String oldValue, String newValue) {
                // Synchronize with cfg.bigendian
                if (newValue.equalsIgnoreCase("big")) {
                    evalConfig.set("cfg.bigendian", "true", false);  // Avoid circular updates
                } else {
                    evalConfig.set("cfg.bigendian", "false", false);  // Avoid circular updates
                }
            }
        });
        
        // Listen for font name changes
        evalConfig.registerListener("scr.font", new R2EvalChangeListener() {
            @Override
            public void onChange(String key, String oldValue, String newValue) {
                updateConsoleFont();
            }
        });
        
        // Listen for font size changes
        evalConfig.registerListener("scr.fontsize", new R2EvalChangeListener() {
            @Override
            public void onChange(String key, String oldValue, String newValue) {
                updateConsoleFont();
            }
        });
    }
    
    /**
     * Get the current address (seek)
     */
    public Address getCurrentAddress() {
        return currentAddress;
    }
    
    /**
     * Set the current address (seek)
     */
    public void setCurrentAddress(Address addr) {
        this.currentAddress = addr;
        
        // Update global state for backwards compatibility
        R4GhidraState.r2Seek = addr;
    }
    
    /**
     * Get the current block size
     */
    public int getBlockSize() {
        return blockSize;
    }
    
    /**
     * Set the current block size
     */
    public void setBlockSize(int size) {
        this.blockSize = size;
        
        // Update global state for backwards compatibility
        R4GhidraState.blockSize = size;
        
        // Update config value to stay in sync
        evalConfig.set("asm.bytes", Integer.toString(size), false); // Avoid circular updates
    }
    
    /**
     * Get the Ghidra API reference
     */
    public FlatProgramAPI getAPI() {
        return api;
    }
    
    /**
     * Set the Ghidra API reference
     */
    public void setAPI(FlatProgramAPI api) {
        this.api = api;
        
        // Update global state for backwards compatibility
        R4GhidraState.api = api;
    }
    
    /**
     * Parse an address string into an Address object
     */
    public Address parseAddress(String addressStr) {
        try {
            // Use R2NumUtil to evaluate complex expressions
            long addrValue = r4ghidra.repl.num.R2NumUtil.evaluateExpression(this, addressStr);
            return api.toAddr(addrValue);
        } catch (r4ghidra.repl.num.R2NumException e) {
            // Fall back to direct conversion if expression evaluation fails
            return api.toAddr(addressStr);
        }
    }
    
    /**
     * Format an address as a hex string
     */
    public String formatAddress(Address addr) {
        return "0x" + String.format("%1$08x", addr.getUnsignedOffset());
    }
    
    /**
     * Format a long value as a hex address string
     */
    public String formatAddress(long addr) {
        return "0x" + String.format("%1$08x", addr);
    }
    
    /**
     * Set an error status
     */
    public void setError(int code, String message) {
        this.lastErrorCode = code;
        this.lastErrorMessage = message;
    }
    
    /**
     * Get the last error code
     */
    public int getLastErrorCode() {
        return lastErrorCode;
    }
    
    /**
     * Get the last error message
     */
    public String getLastErrorMessage() {
        return lastErrorMessage;
    }
    
    /**
     * Clear the error status
     */
    public void clearError() {
        this.lastErrorCode = 0;
        this.lastErrorMessage = "";
    }
    
    /**
     * Set a user-defined variable
     */
    public void setVariable(String name, String value) {
        variables.put(name, value);
    }
    
    /**
     * Get a user-defined variable
     */
    public String getVariable(String name) {
        return variables.getOrDefault(name, "");
    }
    
    /**
     * Check if a variable exists
     */
    public boolean hasVariable(String name) {
        return variables.containsKey(name);
    }
    
    /**
     * Get the configuration manager
     */
    public R2EvalConfig getEvalConfig() {
        return evalConfig;
    }
    
    /**
     * Get the current sandbox flags
     */
    public int getSandboxFlags() {
        return sandboxFlags;
    }
    
    /**
     * Set the sandbox flags
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
    
    /**
     * Update the console font based on current eval settings
     */
    public void updateConsoleFont() {
        if (shellProvider == null) {
            return;  // No UI to update
        }
        
        // Get font settings from config
        String fontName = getEvalConfig().get("scr.font");
        int fontSize = getEvalConfig().getInt("scr.fontsize");
        
        // Check if the font exists
        boolean hasFont = Arrays.asList(
            GraphicsEnvironment.getLocalGraphicsEnvironment()
                .getAvailableFontFamilyNames()
        ).contains(fontName);
        
        // Use monospaced as fallback if font doesn't exist
        if (!hasFont) {
            fontName = Font.MONOSPACED;
        }
        
        // Create the new font
        Font newFont = new Font(fontName, Font.PLAIN, fontSize);
        
        // Apply the font to the UI
        shellProvider.updateFont(newFont);
    }
}