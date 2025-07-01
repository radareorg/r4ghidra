package r4ghidra.repl.filesystem;

/**
 * Exception thrown when a file operation is not allowed by sandbox settings
 * or when there is a problem with in-memory file operations.
 */
public class R2FileSystemException extends Exception {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * Create a new R2FileSystemException with a message
     * 
     * @param message The error message
     */
    public R2FileSystemException(String message) {
        super(message);
    }
    
    /**
     * Create a new R2FileSystemException with a message and cause
     * 
     * @param message The error message
     * @param cause The cause of the exception
     */
    public R2FileSystemException(String message, Throwable cause) {
        super(message, cause);
    }
}