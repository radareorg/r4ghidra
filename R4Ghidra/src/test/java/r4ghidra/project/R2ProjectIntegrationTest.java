package r4ghidra.project;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.json.JSONArray;
import r4ghidra.R4GhidraState;
import r4ghidra.project.R2Project.*;
import r4ghidra.repl.*;

/** Exercises real ProgramDB transactions and the shared shell/HTTP parser without a GUI. */
public class R2ProjectIntegrationTest {
  public static void main(String[] args) throws Exception {
    Application.initializeApplication(
        new GhidraApplicationLayout(new File(args[0])),
        new HeadlessGhidraApplicationConfiguration());
    Object consumer = new Object();
    Language language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    ProgramDB program =
        new ProgramDB("project-test", language, language.getDefaultCompilerSpec(), consumer);
    try {
      Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000);
      int tx = program.startTransaction("Test memory");
      try {
        program
            .getMemory()
            .createInitializedBlock(".text", base, 256, (byte) 0x90, TaskMonitor.DUMMY, false);
      } finally {
        program.endTransaction(tx, true);
      }
      R4GhidraState.api = new FlatProgramAPI(program);
      R2REPLImpl repl = new R2REPLImpl();
      repl.registerCommands(R4CommandInitializer.getCommandHandlers());
      R2Context context = repl.getContext();
      R2Project project = new R2Project();
      project.modules.add(new Mapping(".text", null, 0, 255, 0x1000, 0x10ff, 0));
      project.flags.add(new Flag("test.flag", new Location(0, 0x10), 4));
      project.comments.add(new Comment("imported comment", new Location(0, 0x14), 1));
      project.functions.add(
          new R2Project.Function(
              "test.func",
              new Location(0, 0x20),
              new FunctionAttributes(null, 0, 64, 1, 0),
              List.of(
                  new Block(
                      new Location(0, 0x20), 8, Location.absolute(-1), Location.absolute(-1))),
              List.of()));
      project.xrefs.add(new Xref(new Location(0, 0x20), new Location(0, 0x10), 'd' | (4 << 8)));
      context.getFileSystem().writeBytes("$native", R2ProjectCodec.write(project));
      String imported = repl.executeCommand("prj load $native");
      check(
          imported.startsWith("Imported 1 flags, 1 comments, 1 functions, 1 references"), imported);
      check(context.getFlagAddress("test.flag") == 0x2010, "rebased REPL flag");
      check(
          program.getSymbolTable().getGlobalSymbol("test.flag", base.add(0x10)) != null,
          "rebased label");
      check(
          "imported comment"
              .equals(program.getListing().getComment(CodeUnit.EOL_COMMENT, base.add(0x14))),
          "rebased comment");
      check(
          program.getFunctionManager().getFunctionAt(base.add(0x20)).hasNoReturn(),
          "function attributes");
      check(
          program.getReferenceManager().getReferencesFrom(base.add(0x20)).length == 1,
          "rebased reference");
      testHexdumpJson(program, repl, base);
      r4ghidra.repl.sandbox.R2SandboxIntegrationTest.run(
          repl, Path.of(args[1]).getParent().resolve("sandbox"));
      check(repl.executeCommand("prj?").contains("prj save"), "multi-character help");
      check(repl.executeCommand("? prj").contains("prj save"), "help lookup");
      check(repl.executeCommand("prj load").contains("Usage:"), "missing path");
      check(
          repl.executeCommand("prj save $snapshot").startsWith("Exported"),
          "prj save registration");
      check(
          repl.executeCommand("Ps '$with spaces'").startsWith("Exported"),
          "quoted path and Ps alias");
      check(repl.executeCommand("Po '$with spaces'").startsWith("Imported"), "Po alias");
      R2Project exported = R2ProjectCodec.read(context.getFileSystem().readBytes("$snapshot"));
      check(
          exported.comments.size() == 1
              && exported.functions.size() == 1
              && !exported.xrefs.isEmpty(),
          "Ghidra export");
      check(
          exported.resolve(exported.comments.get(0).location()) == 0x2014,
          "exported relative address");

      Path output = Path.of(args[1]);
      String disk = repl.executeCommand("Ps '" + output + "'");
      check(disk.contains("sandbox"), "default sandbox blocks disk export: " + disk);
      check(
          repl.executeCommand("Po '" + output + "'").contains("sandbox"),
          "default sandbox blocks disk import");
      repl.executeCommand("e cfg.sandbox=false");
      check(
          repl.executeCommand("Ps '" + output + "'").startsWith("Exported"),
          "explicit disk export");
      check(Files.size(output) > 8, "binary file written");
      repl.executeCommand("e cfg.sandbox=true");
      check(repl.executeCommand("Po '" + output + "'").contains("sandbox"), "sandbox re-enabled");

      R2Project bad = new R2Project();
      bad.comments.add(new Comment("must roll back", Location.absolute(0x2014), 1));
      bad.flags.add(new Flag("rollback.flag", Location.absolute(0x2018), 1));
      bad.functions.add(
          new R2Project.Function(
              "bad.function",
              Location.absolute(0x2030),
              null,
              List.of(
                  new Block(
                      Location.absolute(0x2030),
                      0x1000,
                      Location.absolute(-1),
                      Location.absolute(-1))),
              List.of()));
      try {
        R2ProjectService.importProject(
            program, context, R2ProjectCodec.write(bad), TaskMonitor.DUMMY);
        throw new AssertionError("Invalid body accepted");
      } catch (IOException expected) {
        check(
            "imported comment"
                .equals(program.getListing().getComment(CodeUnit.EOL_COMMENT, base.add(0x14))),
            "comment rolled back");
        check(
            program.getSymbolTable().getGlobalSymbol("rollback.flag", base.add(0x18)) == null,
            "label rolled back");
        check(context.getFlagAddress("rollback.flag") == null, "REPL state rolled back");
      }
      R2Project cancelProject = new R2Project();
      cancelProject.flags.add(new Flag("cancel.flag", Location.absolute(0x2018), 1));
      TaskMonitor cancelling =
          new TaskMonitorAdapter() {
            private int checks;

            @Override
            public void checkCancelled() throws CancelledException {
              if (++checks == 3) {
                throw new CancelledException();
              }
            }
          };
      try {
        R2ProjectService.importProject(
            program, context, R2ProjectCodec.write(cancelProject), cancelling);
        throw new AssertionError("Cancellation ignored");
      } catch (CancelledException expected) {
        check(
            program.getSymbolTable().getGlobalSymbol("cancel.flag", base.add(0x18)) == null,
            "cancelled label rolled back");
        check(context.getFlagAddress("cancel.flag") == null, "cancelled REPL state rolled back");
      }
      if (args.length > 2) {
        testNativeImport(language, Files.readAllBytes(Path.of(args[2])));
      }
      System.out.println("RPRJ Ghidra integration tests passed");
    } finally {
      program.release(consumer);
    }
  }

  private static void testHexdumpJson(ProgramDB program, R2REPLImpl repl, Address base)
      throws Exception {
    byte[] bytes = {
      0, 1, 127, (byte) 128, (byte) 255, 16, 32, 48, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74
    };
    int tx = program.startTransaction("JSON hexdump fixture");
    try {
      program.getMemory().setBytes(base.add(0x80), bytes);
    } finally {
      program.endTransaction(tx, true);
    }
    List<Integer> expected =
        List.of(0, 1, 127, 128, 255, 16, 32, 48, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74);
    for (String command : List.of("pxj 19 @0x2080", "xj 19 @0x2080", "p8j 19 @0x2080")) {
      String output = repl.executeCommand(command);
      check(new JSONArray(output).toList().equals(expected), command + " byte array: " + output);
    }
    String output = repl.executeCommand("pxfj @0x2020");
    check(
        new JSONArray(output).toList().equals(List.of(144, 144, 144, 144, 144, 144, 144, 144)),
        "pxfj byte array: " + output);
  }

  private static void testNativeImport(Language language, byte[] data) throws Exception {
    Object consumer = new Object();
    ProgramDB program =
        new ProgramDB("native-test", language, language.getDefaultCompilerSpec(), consumer);
    try {
      Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
      int tx = program.startTransaction("Native test memory");
      try {
        program
            .getMemory()
            .createInitializedBlock("malloc", base, 256, (byte) 0, TaskMonitor.DUMMY, false);
      } finally {
        program.endTransaction(tx, true);
      }
      R2ProjectService.Result result =
          R2ProjectService.importProject(program, null, data, TaskMonitor.DUMMY);
      check(
          result.functions() == 1 && result.comments() == 1 && result.xrefs() == 1,
          "native C project imported into Ghidra");
      check(
          program.getFunctionManager().getFunctionAt(base.add(0x20)).getBody().getNumAddresses()
              == 8,
          "native function body");
      check(
          "native comment"
              .equals(program.getListing().getComment(CodeUnit.EOL_COMMENT, base.add(0x14))),
          "native comment");
    } finally {
      program.release(consumer);
    }
  }

  private static void check(boolean value, String message) {
    R2ProjectCodecTest.check(value, message);
  }
}
