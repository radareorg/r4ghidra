package ghidrar2web.repl;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidrar2web.GhidraR2State;

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

    /**
     * Create a new context with default values
     */
    public R2Context() {
        // We'll initialize these from GhidraR2State for compatibility
        this.api = GhidraR2State.api;
        this.currentAddress = GhidraR2State.r2Seek;
        this.blockSize = GhidraR2State.blockSize;
        
        this.lastErrorCode = 0;
        this.lastErrorMessage = "";
        this.variables = new HashMap<>();
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
        GhidraR2State.r2Seek = addr;
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
        GhidraR2State.blockSize = size;
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
        GhidraR2State.api = api;
    }
    
    /**
     * Parse an address string into an Address object
     */
    public Address parseAddress(String addressStr) {
        return api.toAddr(addressStr);
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
}