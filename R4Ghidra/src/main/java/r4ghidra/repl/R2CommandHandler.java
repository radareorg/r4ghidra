package r4ghidra.repl;

/**
 * Interface for all r2 command handlers
 *
 * <p>Command handlers are responsible for executing a specific command or family of commands. Each
 * handler should implement this interface and be registered with the R2REPLImpl.
 */
public interface R2CommandHandler {

  /**
   * Execute a command
   *
   * @param command The parsed command object
   * @param context The execution context
   * @return The result of the command execution
   * @throws R2CommandException If there's an error during command execution
   */
  String execute(R2Command command, R2Context context) throws R2CommandException;

  /**
   * Get help information for this command
   *
   * @return A string containing help information for this command
   */
  String getHelp();
}
