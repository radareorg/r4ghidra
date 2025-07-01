package r4ghidra.repl.num;

import r4ghidra.repl.R2Context;
import ghidra.program.model.address.Address;

/**
 * Utility class for working with R2Num expressions.
 * 
 * This class provides easy access to the R2Num functionality with convenient
 * factory methods and helpers.
 */
public class R2NumUtil {
    
    /**
     * Create a fully configured R2Num instance for the given context.
     * 
     * @param context The R2 context to use
     * @return A configured R2Num instance ready to use
     */
    public static R2Num createR2Num(R2Context context) {
        // Create the base RNum
        R2Num num = new R2Num(context);
        
        // Configure with symbol resolver
        num.setCallback(new R2GhidraSymbolCallback(context));
        
        // Configure with memory reader
        num.setMemoryReader(new R2GhidraMemoryReader(context));
        
        return num;
    }
    
    /**
     * Evaluate a numeric expression with the given context.
     * 
     * @param context The R2 context to use
     * @param expr The expression to evaluate
     * @return The computed value
     * @throws R2NumException If evaluation fails
     */
    public static long evaluateExpression(R2Context context, String expr) throws R2NumException {
        return createR2Num(context).getValue(expr);
    }
    
    /**
     * Evaluate a numeric expression and convert the result to an Address.
     * 
     * @param context The R2 context to use
     * @param expr The expression to evaluate
     * @return The computed address
     * @throws R2NumException If evaluation fails
     */
    public static Address evaluateAddress(R2Context context, String expr) throws R2NumException {
        long value = evaluateExpression(context, expr);
        return context.getAPI().toAddr(value);
    }
    
    /**
     * Format a numeric value as a hex string.
     * 
     * @param value The value to format
     * @return The formatted hex string (with 0x prefix)
     */
    public static String formatHex(long value) {
        return "0x" + Long.toHexString(value);
    }
}