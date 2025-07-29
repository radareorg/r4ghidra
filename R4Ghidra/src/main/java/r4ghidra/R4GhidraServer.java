package r4ghidra;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import r4ghidra.repl.R4GhidraHttpHandler;

/**
 * HTTP server for R4Ghidra
 *
 * <p>Provides an HTTP interface to R4Ghidra commands, allowing external tools like radare2 to
 * interact with Ghidra via a web API.
 */
public class R4GhidraServer {
  static HttpServer server;

  /**
   * Check if the web server is currently running.
   *
   * @return true if running, false otherwise
   */
  public static boolean isRunning() {
    return server != null;
  }

  static class MyRootHandler implements HttpHandler {
    public void handle(HttpExchange t) throws IOException {

      byte[] response = "Hola".getBytes();
      t.sendResponseHeaders(200, response.length);
      OutputStream os = t.getResponseBody();
      os.write(response);
      os.close();
    }
  }

  /**
   * Start the HTTP server on the specified port
   *
   * @param plugin The R4Ghidra plugin instance that provides command handling
   * @param port The port number to listen on
   * @throws IOException If an error occurs while starting the server
   */
  public static void start(R4GhidraPlugin plugin, int port) throws IOException {
    stop();
    server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/", new MyRootHandler());
    server.createContext("/cmd", new R4GhidraHttpHandler(plugin));
    server.setExecutor(null); // creates a default executor
    server.start();
  }

  /** Stop the HTTP server if it's running */
  public static void stop() {
    if (server != null) {
      server.stop(0);
      server = null;
    }
  }
}
