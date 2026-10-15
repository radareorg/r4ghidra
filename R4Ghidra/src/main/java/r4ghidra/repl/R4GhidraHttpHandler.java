package r4ghidra.repl;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;

/** HTTP handler that processes radare2 commands using the new REPL implementation */
public class R4GhidraHttpHandler implements HttpHandler {

  private R2REPLImpl repl;

  /** Create a new HTTP handler using the shared R4Ghidra command registry. */
  public R4GhidraHttpHandler() {

    repl = new R2REPLImpl();
    repl.registerCommands(R4CommandInitializer.getCommandHandlers());
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    String method = exchange.getRequestMethod();
    if (!"GET".equalsIgnoreCase(method) && !"POST".equalsIgnoreCase(method)) {
      sendErrorResponse(400, exchange, "Invalid request".getBytes(StandardCharsets.UTF_8));
      return;
    }

    // Use the same URI command for GET and POST, retaining query-string precedence.
    String cmd = exchange.getRequestURI().getQuery();
    if (cmd == null) {
      String path = exchange.getRequestURI().getPath();
      cmd = path.length() > 5 ? path.substring(5) : "";
    }

    if ("POST".equalsIgnoreCase(method)) {
      // The raw UTF-8 body either completes the URI command or supplies the whole command.
      try (InputStream is = exchange.getRequestBody()) {
        String body =
            StandardCharsets.UTF_8
                .newDecoder()
                .decode(ByteBuffer.wrap(is.readAllBytes()))
                .toString();
        if (!body.isEmpty()) {
          cmd += (cmd.isEmpty() ? "" : " ") + body;
        }
      } catch (MalformedInputException mie) {
        sendErrorResponse(
            400, exchange, "Invalid UTF-8 encoding!".getBytes(StandardCharsets.UTF_8));
        return;
      }
    }

    if (cmd.trim().isEmpty()) {
      sendErrorResponse(400, exchange, "Empty request".getBytes(StandardCharsets.UTF_8));
      return;
    }

    try {
      // Execute the command using our REPL implementation
      String result = repl.executeCommand(cmd);
      sendResponse(exchange, result.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      // Handle any unexpected exceptions
      sendErrorResponse(
          500,
          exchange,
          ("Error executing command: " + e.getMessage()).getBytes(StandardCharsets.UTF_8));
    }
  }

  private void setResponseHeaders(HttpExchange exchange) {
    Headers headers = exchange.getResponseHeaders();
    headers.add("Accept-Charset", "UTF-8");
    headers.add("Accept-Encoding", "identity");
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
