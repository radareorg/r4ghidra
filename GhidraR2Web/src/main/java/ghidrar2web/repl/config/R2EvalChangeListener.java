package ghidrar2web.repl.config;

/**
 * Interface for listeners that respond to configuration variable changes
 */
public interface R2EvalChangeListener {
    
    /**
     * Called when a configuration variable changes
     * 
     * @param key The variable name
     * @param oldValue The previous value
     * @param newValue The new value
     */
    void onChange(String key, String oldValue, String newValue);
}