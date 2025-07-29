package r4ghidra.repl;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import r4ghidra.repl.handlers.R2BlocksizeCommandHandler;
import r4ghidra.repl.handlers.R2EnvCommandHandler;
import r4ghidra.repl.handlers.R2EvalCommandHandler;
import r4ghidra.repl.handlers.R2HelpCommandHandler;
import r4ghidra.repl.handlers.R2JsCommandHandler;
import r4ghidra.repl.handlers.R2PrintCommandHandler;
import r4ghidra.repl.handlers.R2SeekCommandHandler;
import r4ghidra.repl.handlers.R2ShellCommandHandler;
import r4ghidra.R4GhidraPlugin;

/** HTTP handler that processes radare2 commands using the new REPL implementation */
public class R4GhidraHttpHandler implements HttpHandler {

  private R2REPLImpl repl;
  private Map<String, R2CommandHandler> commandRegistry;

  /** Create a new handler */
  /**
   * Create a new HTTP handler for R4Ghidra
   *
   * @param plugin The R4Ghidra plugin instance that provides command handlers
   */
  public R4GhidraHttpHandler(R4GhidraPlugin plugin) {
    commandRegistry = new HashMap<>();

    repl = new R2REPLImpl();
    repl.registerCommands (plugin.getCommandHandlers());
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    // Extract command from query string or path
    String cmd = exchange.getRequestURI().getQuery();
    if (cmd == null) {
      cmd = exchange.getRequestURI().getPath().substring(5);
    }

    if (cmd == null || cmd.isEmpty()) {
      sendErrorResponse(400, exchange, "Empty request".getBytes());
      return;
    }

    try {
      // Execute the command using our REPL implementation
      String result = repl.executeCommand(cmd);
      sendResponse(exchange, result.getBytes());
    } catch (Exception e) {
      // Handle any unexpected exceptions
      sendErrorResponse(500, exchange, ("Error executing command: " + e.getMessage()).getBytes());
    }
  }

  /** Send a successful response */
  private void sendResponse(HttpExchange exchange, byte[] response) throws IOException {
    exchange.sendResponseHeaders(200, response.length);
    OutputStream os = exchange.getResponseBody();
    os.write(response);
    os.close();
  }

  /** Send an error response */
  private void sendErrorResponse(int status, HttpExchange exchange, byte[] response)
      throws IOException {
    exchange.sendResponseHeaders(status, response.length);
    OutputStream os = exchange.getResponseBody();
    os.write(response);
    os.close();
  }
}
