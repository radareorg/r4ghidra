package r4ghidra;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import r4ghidra.repl.R4GhidraREPLHandler;


public class R4GhidraServer {
	static HttpServer server;

	static class MyRootHandler implements HttpHandler {
		public void handle(HttpExchange t) throws IOException {

			byte[] response = "Hola".getBytes();
			t.sendResponseHeaders(200, response.length);
			OutputStream os = t.getResponseBody();
			os.write(response);
			os.close();

		}
	}

	public static void start(int port) throws IOException {
		stop();
		server = HttpServer.create(new InetSocketAddress(port), 0);
		server.createContext("/", new MyRootHandler());
		// server.createContext("/cmd", new R4GhidraCmdHandler()); // old
		server.createContext("/cmd", new R4GhidraREPLHandler());
		server.setExecutor(null); // creates a default executor
		server.start();	
		
	} 
	
	public static void stop() {
		if (server != null) {
			server.stop(0);
			server = null;
		}
	}
}
