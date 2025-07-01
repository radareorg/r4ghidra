package r4ghidra.repl.num;

/**
 * Callback interface for resolving symbol names in R2Num expressions.
 * 
 * This interface allows external components to provide values for symbolic
 * names used in radare2 numeric expressions, such as function names, variables, etc.
 */
public interface R2NumCallback {
    /**
     * Resolve a symbol name to its numeric value
     * 
     * @param name The symbol name to resolve
     * @return The numeric value of the symbol, or null if the symbol cannot be resolved
     */
    Long resolveSymbol(String name);
}