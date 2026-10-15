package r4ghidra.repl.sandbox;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import r4ghidra.repl.R2Context;
import r4ghidra.repl.R2REPLImpl;
import r4ghidra.repl.config.R2EvalConfig;
import r4ghidra.repl.filesystem.R2FileSystem;
import r4ghidra.repl.filesystem.R2FileSystemException;
import r4ghidra.repl.handlers.R2JsCommandHandler;

/** Exercises the real parser and filesystem against temporary files and a Ghidra context. */
public final class R2SandboxIntegrationTest {
  public static void run(R2REPLImpl repl, Path directory) throws Exception {
    Files.createDirectories(directory);
    Path plain = directory.resolve("plain.txt");
    Files.writeString(plain, "fixture");
    Path script = directory.resolve("script with spaces.r2");
    Files.writeString(script, "echo from-script\n");
    Path js = directory.resolve("script.r2.js");
    Files.writeString(js, "1+1");
    R2Context context = repl.getContext();
    R2EvalConfig config = context.getEvalConfig();
    R2FileSystem fs = context.getFileSystem();
    repl.registerCommand("js", new R2JsCommandHandler());

    check(config.get("cfg.sandbox.grain").equals("none"), "default grain");
    for (String command :
        List.of(
            "!echo denied",
            "!!echo denied",
            ".!echo denied",
            "echo denied | cat",
            "%",
            "%*",
            "%j",
            "%PATH",
            "%R4GHIDRA_SANDBOX_TEST=denied",
            ". '" + script + "'",
            ". '" + js + "'",
            "js 1+1",
            "q 23",
            "q!!")) {
      denied(repl, command);
    }
    check(repl.executeCommand("!").contains("echo denied"), "history stays available");
    check(!fs.fileExists(plain.toString()), "blocked metadata");
    blocked(() -> fs.readFile(plain.toString()));
    blocked(() -> fs.readBytes(plain.toString()));
    blocked(() -> fs.listFiles(directory.toString()));

    // Memory files remain usable with no host permissions, including script loading.
    fs.writeFile("$sandbox", "echo memory-script\n");
    check(repl.executeCommand(". $sandbox").equals("memory-script\n"), "memory script");
    repl.executeCommand("echo memory > $output");
    check(fs.readFile("$output").equals("memory\n"), "memory redirection");
    fs.writeBytes("$binary", new byte[] {0, (byte) 255});
    check(fs.readBytes("$binary")[1] == (byte) 255, "memory bytes");

    check(repl.executeCommand("e cfg.sandbox.grain=?").contains("!name"), "grain help");
    check(config.get("cfg.sandbox.grain").equals("none"), "help does not change policy");
    repl.executeCommand("e sandbox.grain=files");
    check(config.get("sandbox.grain").equals("files"), "short alias");
    check(config.get("cfg.sandbox.grain").equals("files"), "canonical grain");
    check(fs.readFile(plain.toString()).equals("fixture"), "files permits text reads");
    check(fs.readBytes(plain.toString()).length == 7, "files permits binary reads");
    check(fs.fileExists(plain.toString()), "files permits metadata");
    check(fs.listFiles(directory.toString()).contains(plain.toString()), "files permits listing");
    check(repl.executeCommand(". '" + script + "'").equals("from-script\n"), "disk script");
    blocked(() -> fs.writeFile(plain.toString(), "changed"));
    blocked(() -> fs.writeBytes(plain.toString(), new byte[] {1}));
    blocked(() -> fs.appendFile(plain.toString(), "changed"));
    blocked(() -> fs.deleteFile(plain.toString()));
    denied(repl, "echo changed > " + plain);
    denied(repl, "echo changed >> " + plain);
    check(Files.readString(plain).equals("fixture"), "blocked writes leave file intact");
    denied(repl, "js 1+1");

    // Reject invalid values before they can change either config or the active policy.
    for (String invalid : List.of("rw", "files,garbage", "files,", "")) {
      String result = repl.executeCommand("e cfg.sandbox.grain=" + invalid);
      check(result.startsWith("Error:"), "invalid grain rejected: " + result);
      check(config.get("cfg.sandbox.grain").equals("files"), "invalid grain preserves config");
      blocked(() -> fs.writeFile(plain.toString(), "changed"));
    }
    check(repl.executeCommand("e cfg.sandbox=typo").startsWith("Error:"), "invalid boolean");
    check(config.getBoolean("cfg.sandbox"), "invalid boolean preserves sandbox");

    repl.executeCommand("e cfg.sandbox.grain = files, disk");
    fs.writeFile(plain.toString(), "one");
    fs.appendFile(plain.toString(), "two");
    check(fs.readFile(plain.toString()).equals("onetwo"), "disk writes and append");
    fs.writeBytes(plain.toString(), new byte[] {0, (byte) 255});
    check(fs.readBytes(plain.toString())[1] == (byte) 255, "disk bytes");
    fs.deleteFile(plain.toString());
    check(!Files.exists(plain), "disk deletion");
    repl.executeCommand("e cfg.sandbox.grain=disk");
    blocked(() -> fs.writeFile(plain.toString(), "changed"));
    check(!Files.exists(plain), "disk without files cannot create files");

    testHiddenFiles(repl, directory);

    repl.executeCommand("e cfg.sandbox.grain=exec");
    check(
        repl.executeCommand("!!printf '%s' 'hello world'").equals("hello world\n"),
        "shell arguments");
    check(repl.executeCommand("!true").contains("code: 0"), "interactive shell");
    check(repl.executeCommand(".!echo echo from-shell").equals("from-shell\n"), "shell script");
    check(repl.executeCommand("echo piped | cat").equals("piped\n"), "external pipe");
    denied(repl, "%PATH");
    denied(repl, "js 1+1");
    // Recheck the permission after the left command, before spawning the pipe process.
    denied(repl, "e cfg.sandbox.grain=none | cat");
    check(config.get("cfg.sandbox.grain").equals("none"), "pipe left side narrowed permissions");
    denied(repl, "e cfg.sandbox=false | cat");
    check(config.getBoolean("cfg.sandbox"), "denied pipe never executes its left side");

    repl.executeCommand("e cfg.sandbox.grain=environ");
    String environment = repl.executeCommand("%j");
    check(new org.json.JSONObject(environment).length() > 0, "environment grain");
    denied(repl, "!!echo denied");

    // Turning the local sandbox off and on preserves the chosen grain.
    repl.executeCommand("e cfg.sandbox=off");
    check(!context.isSandboxed(R2Context.R_SANDBOX_GRAIN_ALL), "sandbox off");
    repl.executeCommand("e cfg.sandbox=ON");
    check(config.get("cfg.sandbox.grain").equals("environ"), "grain survives toggle");
    denied(repl, "!!echo denied");
    repl.executeCommand("e cfg.sandbox.grain=all");
    check(repl.executeCommand("js 1+1").equals("2\n"), "explicit unrestricted JavaScript");
    check(repl.executeCommand(". '" + js + "'").equals("2\n"), "JavaScript file");

    context.setSandboxFlags(R2Context.R_SANDBOX_GRAIN_ALL & ~R2Context.R_SANDBOX_GRAIN_FILES);
    check(config.get("cfg.sandbox.grain").equals("files"), "restriction API synchronizes config");
    // Suppressed listeners must not bypass sandbox validation or enforcement.
    config.set("cfg.sandbox.grain", "none", false);
    blocked(() -> fs.readFile(script.toString()));
    System.out.println("Sandbox command integration tests passed");
  }

  private static void testHiddenFiles(R2REPLImpl repl, Path directory) throws Exception {
    R2FileSystem fs = repl.getContext().getFileSystem();
    Path hidden = Files.createDirectories(directory.resolve(".hidden"));
    Path secret = hidden.resolve("secret");
    Files.writeString(secret, "secret");
    Path alias = directory.resolve("alias");
    Files.createSymbolicLink(alias, hidden);
    repl.executeCommand("e cfg.sandbox.grain=files,disk");
    for (Path path : List.of(secret, alias.resolve("secret"))) {
      blocked(() -> fs.readFile(path.toString()));
      blocked(() -> fs.readBytes(path.toString()));
      blocked(() -> fs.writeFile(path.toString(), "changed"));
      blocked(() -> fs.deleteFile(path.toString()));
      check(!fs.fileExists(path.toString()), "hidden metadata blocked");
    }
    blocked(() -> fs.writeBytes(alias.resolve("new").toString(), new byte[] {1}));
    blocked(() -> fs.listFiles(alias.toString()));
    List<String> visible = fs.listFiles(directory.toString());
    check(
        !visible.contains(hidden.toString()) && !visible.contains(alias.toString()),
        "hidden listing filtered");
    check(Files.readString(secret).equals("secret"), "hidden file untouched");
    check(!Files.exists(hidden.resolve("new")), "hidden target not created");
    repl.executeCommand("e cfg.sandbox.grain=files,disk,hidden");
    check(fs.readFile(secret.toString()).equals("secret"), "hidden grant");
    check(fs.readFile(alias.resolve("secret").toString()).equals("secret"), "hidden symlink grant");
  }

  private static void denied(R2REPLImpl repl, String command) {
    String result = repl.executeCommand(command);
    check(result.startsWith("Error:") && result.contains("sandbox"), command + ": " + result);
  }

  private static void blocked(Operation operation) throws Exception {
    try {
      operation.run();
      throw new AssertionError("Sandbox operation allowed");
    } catch (R2FileSystemException expected) {
      // Expected.
    }
  }

  private interface Operation {
    void run() throws Exception;
  }

  private static void check(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }
}
