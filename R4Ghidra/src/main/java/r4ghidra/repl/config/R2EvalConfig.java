package r4ghidra.repl.config;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import r4ghidra.repl.R2Context;

/**
 * Configuration management for R2 eval variables
 * 
 * This class manages the configuration variables for the R2 environment,
 * similar to how r2's "e" command works. It provides variable storage,
 * type conversion, change listeners, and default values.
 */
public class R2EvalConfig {
    
    // The parent context
    private R2Context context;
    
    // Map of configuration variables
    private Map<String, String> config;
    
    // Map of variable change listeners
    private Map<String, R2EvalChangeListener> listeners;
    
    // Lock status - when true, config options cannot be created
    private boolean locked = false;
    
    /**
     * Create a new configuration manager
     * 
     * @param context The R2 context to associate with
     */
    public R2EvalConfig(R2Context context) {
        this.context = context;
        this.config = new HashMap<>();
        this.listeners = new HashMap<>();
        
        // Initialize with default values
        initDefaults();
    }
    
    /**
     * Set default configuration values
     */
    private void initDefaults() {
        // Architecture and assembly settings
        set("asm.arch", "x86", false);
        set("asm.bits", "32", false);
        set("asm.cpu", "default", false);
        set("asm.bytes", "16", false);
        
        // Configuration settings
        set("cfg.bigendian", "false", false);
        set("cfg.endian", "little", false);
        set("cfg.sandbox", "false", false);
        set("cfg.sandbox.grain", "rw", false);
        
        // Screen settings
        set("scr.color", "1", false);
        set("scr.prompt", "true", false);
        set("scr.font", "STMono", false);
        set("scr.fontsize", "12", false);
        
        // Directory settings
        set("dir.tmp", "/tmp", false);
        
        // HTTP settings
        set("http.port", "8080", false);
        
        // IO settings
        set("io.cache", "false", false);
    }
    
    /**
     * Register a change listener for a variable
     * 
     * @param key The variable name
     * @param listener The listener to call when the variable changes
     */
    public void registerListener(String key, R2EvalChangeListener listener) {
        listeners.put(key, listener);
    }
    
    /**
     * Get all configuration keys
     * 
     * @return Set of all configuration keys
     */
    public Set<String> getKeys() {
        return config.keySet();
    }
    
    /**
     * Get all configuration variables as a sorted map
     * 
     * @return Sorted map of all configuration variables
     */
    public Map<String, String> getAll() {
        return new TreeMap<>(config);
    }
    
    /**
     * Get all configuration variables that start with a prefix
     * 
     * @param prefix The prefix to match
     * @return Map of matching configuration variables
     */
    public Map<String, String> getByPrefix(String prefix) {
        Map<String, String> result = new TreeMap<>();
        
        for (Map.Entry<String, String> entry : config.entrySet()) {
            if (entry.getKey().startsWith(prefix)) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        
        return result;
    }
    
    /**
     * Set a configuration variable
     * 
     * @param key The variable name
     * @param value The value to set
     * @return true if the value was changed, false otherwise
     */
    public boolean set(String key, String value) {
        return set(key, value, true);
    }
    
    /**
     * Set a configuration variable with an integer value
     * 
     * @param key The variable name
     * @param value The integer value to set
     * @return true if the value was changed, false otherwise
     */
    public boolean set(String key, int value) {
        return set(key, Integer.toString(value));
    }
    
    /**
     * Set a configuration variable with a long (uint64) value
     * 
     * @param key The variable name
     * @param value The long value to set
     * @return true if the value was changed, false otherwise
     */
    public boolean set(String key, long value) {
        return set(key, Long.toString(value));
    }
    
    /**
     * Set a configuration variable with a boolean value
     * 
     * @param key The variable name
     * @param value The boolean value to set
     * @return true if the value was changed, false otherwise
     */
    public boolean set(String key, boolean value) {
        return set(key, value ? "true" : "false");
    }
    
    /**
     * Set a configuration variable with option to trigger listeners
     * 
     * @param key The variable name
     * @param value The value to set
     * @param triggerListeners Whether to trigger change listeners
     * @return true if the value was changed, false otherwise
     */
    public boolean set(String key, String value, boolean triggerListeners) {
        // Normalize key
        key = key.trim().toLowerCase();
        
        // If configuration is locked and this is a new key, deny the operation
        if (locked && !config.containsKey(key)) {
            return false;  // Configuration is locked, can't create new keys
        }
        // Check if the value is actually changing
        String oldValue = config.get(key);
        if (value.equals(oldValue)) {
            return false;  // No change
        }
        
        // Update the value
        config.put(key, value);
        
        // Trigger change listener if applicable
        if (triggerListeners && listeners.containsKey(key)) {
            listeners.get(key).onChange(key, oldValue, value);
        }
        
        return true;
    }
    
    /**
     * Get a configuration variable
     * 
     * @param key The variable name
     * @return The value, or empty string if not found
     */
    public String get(String key) {
        return config.getOrDefault(key.trim().toLowerCase(), "");
    }
    
    /**
     * Check if a configuration variable exists
     * 
     * @param key The variable name
     * @return true if the variable exists, false otherwise
     */
    public boolean contains(String key) {
        return config.containsKey(key.trim().toLowerCase());
    }
    
    /**
     * Get a configuration variable as a boolean
     * 
     * @param key The variable name
     * @return The boolean value, or false if not a valid boolean
     */
    public boolean getBoolean(String key) {
        String value = get(key);
        
        // Check for true/false
        if (value.equalsIgnoreCase("true") || value.equals("1") || 
            value.equalsIgnoreCase("yes") || value.equalsIgnoreCase("on") || 
            value.equalsIgnoreCase("y")) {
            return true;
        }
        
        // Check for numeric values > 0
        try {
            int numValue = Integer.parseInt(value);
            if (numValue > 0) {
                return true;
            }
        } catch (NumberFormatException e) {
            // Not a number, ignore and continue
        }
        
        // Everything else is false
        return false;
    }
    
    /**
     * Get a configuration variable as a boolean
     * 
     * @param key The variable name
     * @param defaultValue The default value to return if the key doesn't exist or isn't a valid boolean
     * @return The boolean value, or the default value if not a valid boolean
     */
    public boolean getBool(String key, boolean defaultValue) {
        if (!contains(key)) {
            return defaultValue;
        }
        return getBoolean(key);
    }
    
    /**
     * Get a configuration variable as an integer
     * 
     * @param key The variable name
     * @return The integer value, or 0 if not a valid integer
     */
    public int getInt(String key) {
        try {
            return Integer.parseInt(get(key));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    /**
     * Get a configuration variable as a long
     * 
     * @param key The variable name
     * @return The long value, or 0 if not a valid long
     */
    public long getLong(String key) {
        try {
            return Long.parseLong(get(key));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    /**
     * Lock the configuration to prevent creation of new keys
     * Only existing keys can be modified after locking
     */
    public void lock() {
        this.locked = true;
    }
    
    /**
     * Unlock the configuration to allow creation of new keys
     * This should only be called by plugins or extensions
     */
    public void unlock() {
        this.locked = false;
    }
    
    /**
     * Check if the configuration is locked
     * 
     * @return true if locked, false if unlocked
     */
    public boolean isLocked() {
        return this.locked;
    }
}