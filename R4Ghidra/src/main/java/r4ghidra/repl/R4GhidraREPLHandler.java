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
import r4ghidra.repl.handlers.R2PrintCommandHandler;
import r4ghidra.repl.handlers.R2SeekCommandHandler;
import r4ghidra.repl.handlers.R2ShellCommandHandler;

/** HTTP handler that processes radare2 commands using the new REPL implementation */
public class R4GhidraREPLHandler implements HttpHandler {

private R2REPLImpl repl;
private Map<String, R2CommandHandler> commandRegistry;

/** Create a new handler */
public R4GhidraREPLHandler() {
	repl = new R2REPLImpl();
	commandRegistry = new HashMap<>();

	// Register command handlers
	registerCommandHandlers();
}

/** Register all available command handlers */
private void registerCommandHandlers() {
	// Register the 'help' command first since it needs access to the command registry
	R2HelpCommandHandler helpHandler = new R2HelpCommandHandler(commandRegistry);
	commandRegistry.put("?", helpHandler);
	repl.registerCommand("?", helpHandler);

	// Basic commands
	R2SeekCommandHandler seekHandler = new R2SeekCommandHandler();
	commandRegistry.put("s", seekHandler);
	repl.registerCommand("s", seekHandler);

	// Print commands
	R2PrintCommandHandler printHandler = new R2PrintCommandHandler();
	commandRegistry.put("p", printHandler);
	repl.registerCommand("p", printHandler);

	// Shell commands
	R2ShellCommandHandler shellHandler = new R2ShellCommandHandler();
	commandRegistry.put("!", shellHandler);
	repl.registerCommand("!", shellHandler);

	// Environment variable commands
	R2EnvCommandHandler envHandler = new R2EnvCommandHandler();
	commandRegistry.put("%", envHandler);
	repl.registerCommand("%", envHandler);

	// Eval configuration commands
	R2EvalCommandHandler evalHandler = new R2EvalCommandHandler();
	commandRegistry.put("e", evalHandler);
	repl.registerCommand("e", evalHandler);

	// Blocksize commands
	R2BlocksizeCommandHandler blocksizeHandler = new R2BlocksizeCommandHandler();
	commandRegistry.put("b", blocksizeHandler);
	repl.registerCommand("b", blocksizeHandler);

	// Add more command handlers here as they're implemented
	// ...
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
