package r4ghidra;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/** Exercises GET, POST and URI/body command composition through the real HTTP server and REPL. */
public class R4GhidraHttpHandlerTest {
  public static void main(String[] args) throws Exception {
    Application.initializeApplication(
        new GhidraApplicationLayout(new File(args[0])),
        new HeadlessGhidraApplicationConfiguration());
    Object consumer = new Object();
    Language language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    ProgramDB program =
        new ProgramDB("http-test", language, language.getDefaultCompilerSpec(), consumer);
    try {
      Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
      int tx = program.startTransaction("Test memory");
      try {
        program
            .getMemory()
            .createInitializedBlock(".text", base, 16, (byte) 0, TaskMonitor.DUMMY, false);
      } finally {
        program.endTransaction(tx, true);
      }
      R4GhidraState.api = new FlatProgramAPI(program);
      R4GhidraServer.start(0);
      if (!R4GhidraServer.server.getAddress().getAddress().isLoopbackAddress()) {
        throw new AssertionError("HTTP server must bind to loopback");
      }
      String url = "http://localhost:" + R4GhidraServer.server.getAddress().getPort();
      try (HttpClient client = HttpClient.newHttpClient()) {
        check(client, url, "GET", "/cmd/echo%20hello", "", 200, "hello\n");
        check(client, url, "GET", "/cmd/?echo%20hello", "", 200, "hello\n");
        check(client, url, "GET", "/cmd/%3Fe%20hello", "", 200, "hello\n");
        check(client, url, "POST", "/cmd", "echo hello", 200, "hello\n");
        check(client, url, "POST", "/cmd/", "echo hello", 200, "hello\n");
        check(client, url, "POST", "/cmd/echo", "hello", 200, "hello\n");
        check(client, url, "POST", "/cmd/echo%20hello", "world", 200, "hello world\n");
        check(client, url, "POST", "/cmd/ignored?echo", "hello", 200, "hello\n");
        check(client, url, "POST", "/cmd/echo%20hello", "", 200, "hello\n");
        check(client, url, "POST", "/cmd/?echo%20hello", "", 200, "hello\n");
        check(client, url, "POST", "/cmd/echo", "", 200, "\n");
        check(client, url, "POST", "/cmd/%3Fe", "hello", 200, "hello\n");
        check(client, url, "POST", "/cmd/echo%20%CE%BB", "привет", 200, "λ привет\n");
        check(client, url, "POST", "/cmd/echo", "a+b%20c&x=y", 200, "a+b%20c&x=y\n");
        check(client, url, "POST", "/cmd/echo%20a+b%2520c", "end", 200, "a+b%20c end\n");
        check(client, url, "GET", "/cmd/", "", 400, "Empty request");
        check(client, url, "POST", "/cmd", "", 400, "Empty request");
        check(client, url, "POST", "/cmd/", " \t\r\n", 400, "Empty request");
        check(client, url, "PUT", "/cmd/echo", "hello", 400, "Invalid request");
        check(
            client,
            url,
            "POST",
            "/cmd/echo",
            new byte[] {(byte) 0xc3, 0x28},
            400,
            "Invalid UTF-8 encoding!");
        // Confirm that rejecting a malformed request does not break subsequent commands.
        check(client, url, "POST", "/cmd/echo", "hello", 200, "hello\n");
        check(
            client,
            url,
            "GET",
            "/cmd/e%20cfg.sandbox=false",
            "",
            200,
            "Error: Cannot disable a locked sandbox");
        check(
            client,
            url,
            "POST",
            "/cmd",
            "e cfg.sandbox.grain=exec;!!echo denied",
            200,
            "Error: Cannot increase locked sandbox permissions\n"
                + "Error: Shell execution not allowed by sandbox settings\n");
        check(
            client,
            url,
            "POST",
            "/cmd",
            "e sandbox.grain=all",
            200,
            "Error: Cannot increase locked sandbox permissions");
        check(
            client,
            url,
            "POST",
            "/cmd",
            "echo denied | cat",
            200,
            "Error: External pipe execution not allowed by sandbox settings");
        check(
            client,
            url,
            "POST",
            "/cmd",
            "%PATH",
            200,
            "Error: Environment access not allowed by sandbox settings");
        check(
            client,
            url,
            "POST",
            "/cmd",
            "q 23",
            200,
            "Error: Process exit not allowed by sandbox settings");
        check(
            client,
            url,
            "POST",
            "/cmd",
            "Ps $snapshot",
            200,
            "Exported 0 flags, 0 comments, 0 functions, 0 references\n");
        check(client, url, "POST", "/cmd", "echo still-alive", 200, "still-alive\n");
        System.out.println("HTTP command regression tests passed");
      }
    } finally {
      R4GhidraServer.stop();
      R4GhidraState.api = null;
      program.release(consumer);
    }
  }

  private static void check(
      HttpClient client,
      String url,
      String method,
      String path,
      String body,
      int status,
      String expected)
      throws Exception {
    check(client, url, method, path, body.getBytes(StandardCharsets.UTF_8), status, expected);
  }

  private static void check(
      HttpClient client,
      String url,
      String method,
      String path,
      byte[] body,
      int status,
      String expected)
      throws Exception {
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(url + path))
            .timeout(Duration.ofSeconds(5))
            .method(method, HttpRequest.BodyPublishers.ofByteArray(body))
            .build();
    HttpResponse<String> response =
        client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    if (response.statusCode() != status || !response.body().equals(expected)) {
      throw new AssertionError(
          method + " " + path + ": HTTP " + response.statusCode() + " " + response.body());
    }
  }
}
