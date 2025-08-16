package r4ghidra.repl;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
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
    // Support POST requests (body contains the command) and fallback to GET/query/path
    String method = exchange.getRequestMethod();
    String cmd = null;

    if ("POST".equalsIgnoreCase(method)) {
      // Read the entire request body as the command (assume UTF-8)
      java.io.InputStream is = exchange.getRequestBody();
      try {
        byte[] body = is.readAllBytes();
        CharsetDecoder charsetDecoder = StandardCharsets.UTF_8.newDecoder();
        CharBuffer decodedCharBuffer = charsetDecoder.decode(ByteBuffer.wrap(body));
        cmd = decodedCharBuffer.toString().trim();
      } catch(MalformedInputException mie){
        sendErrorResponse(400, exchange, "Invalid UTF-8 encoding!".getBytes());
        return;
      }finally {
        is.close();
      }
    } else if ("GET".equalsIgnoreCase(method)){
      // Extract command from query string or path (existing behavior)
      cmd = exchange.getRequestURI().getQuery();
      if (cmd == null) {
        String path = exchange.getRequestURI().getPath();
        if (path.length() > 5) {
          cmd = path.substring(5);
        } else {
          cmd = "";
        }
      }
    } else {
      sendErrorResponse(400, exchange, "Invalid request".getBytes());
      return;
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

  private void setResponseHeaders(HttpExchange exchange){
    Headers headers=exchange.getResponseHeaders();
    headers.add("Accept-Charset","UTF-8");
    headers.add("Accept-Encoding","identity");
  }
  /** Send a successful response */
  private void sendResponse(HttpExchange exchange, byte[] response) throws IOException {
    setResponseHeaders(exchange);
    exchange.sendResponseHeaders(200, response.length);
    OutputStream os = exchange.getResponseBody();
    os.write(response);
    os.close();
  }

  /** Send an error response */
  private void sendErrorResponse(int status, HttpExchange exchange, byte[] response)
      throws IOException {
    setResponseHeaders(exchange);
    exchange.sendResponseHeaders(status, response.length);
    OutputStream os = exchange.getResponseBody();
    os.write(response);
    os.close();
  }
}
