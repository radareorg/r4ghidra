package r4ghidra.repl;

/** Exception thrown during command parsing or execution */
public class R2CommandException extends Exception {

private static final long serialVersionUID = 1L;

private int errorCode;

/**
* Create a new exception with the given message
*
* @param message The error message
*/
public R2CommandException(String message) {
	this(1, message);
}

/**
* Create a new exception with the given error code and message
*
* @param errorCode The error code
* @param message The error message
*/
public R2CommandException(int errorCode, String message) {
	super(message);
	this.errorCode = errorCode;
}

/**
* Create a new exception with the given message and cause
*
* @param message The error message
* @param cause The cause of the exception
*/
public R2CommandException(String message, Throwable cause) {
	this(1, message, cause);
}

/**
* Create a new exception with the given error code, message, and cause
*
* @param errorCode The error code
* @param message The error message
* @param cause The cause of the exception
*/
public R2CommandException(int errorCode, String message, Throwable cause) {
	super(message, cause);
	this.errorCode = errorCode;
}

/**
* Get the error code
*
* @return The error code
*/
public int getErrorCode() {
	return errorCode;
}
}
