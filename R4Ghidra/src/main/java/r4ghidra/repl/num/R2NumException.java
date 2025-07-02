package r4ghidra.repl.num;

/** Exception thrown during RNum expression evaluation. */
public class R2NumException extends Exception {
private static final long serialVersionUID = 1L;

/**
* Create a new RNum exception with a message
*
* @param message The exception message
*/
public R2NumException(String message) {
	super(message);
}

/**
* Create a new RNum exception with a message and cause
*
* @param message The exception message
* @param cause The cause of the exception
*/
public R2NumException(String message, Throwable cause) {
	super(message, cause);
}
}
