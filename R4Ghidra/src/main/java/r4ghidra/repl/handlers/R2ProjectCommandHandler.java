package r4ghidra.repl.handlers;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import r4ghidra.project.*;
import r4ghidra.repl.*;

/** Native binary project import/export, shared by the shell and HTTP command parser. */
public class R2ProjectCommandHandler implements R2CommandHandler {
  @Override
  public String[] getPrefixes() {
    return new String[] {"prj", "P"};
  }

  @Override
  public String execute(R2Command command, R2Context context) throws R2CommandException {
    String action;
    String path;
    if (command.hasPrefix("prj")) {
      if (command.getArgumentCount() == 0 && command.getSubcommand().isEmpty()) {
        return getHelp();
      }
      if (!command.getSubcommand().isEmpty() || command.getArgumentCount() != 2) {
        throw new R2CommandException("Usage: prj load|save <file>");
      }
      action = command.getArgument(0, "");
      path = command.getArgument(1, "");
    } else if (command.hasPrefix("P")) {
      if (command.getSubcommand().isEmpty() && command.getArgumentCount() == 0) {
        return getHelp();
      }
      if (command.getArgumentCount() != 1) {
        throw new R2CommandException("Usage: Po|Ps <file>");
      }
      action =
          switch (command.getSubcommand()) {
            case "o" -> "load";
            case "s" -> "save";
            default -> "";
          };
      path = command.getFirstArgument("");
    } else {
      throw new R2CommandException("Not a project command");
    }
    if (path.isEmpty() || !(action.equals("load") || action.equals("save"))) {
      throw new R2CommandException("Usage: prj load|save <file>");
    }
    try {
      Program program = context.getAPI().getCurrentProgram();
      if (program == null) {
        throw new R2CommandException("Open a program before importing or exporting a project");
      }
      if (action.equals("load")) {
        R2ProjectService.Result result =
            R2ProjectService.importProject(
                program, context, context.getFileSystem().readBytes(path), TaskMonitor.DUMMY);
        return "Imported " + result.describe();
      }
      R2Project project = R2ProjectService.exportProject(program, context, TaskMonitor.DUMMY);
      context.getFileSystem().writeBytes(path, R2ProjectCodec.write(project));
      return "Exported "
          + new R2ProjectService.Result(
                  project.flags.size(),
                  project.comments.size(),
                  project.functions.size(),
                  project.xrefs.size(),
                  project.warnings)
              .describe();
    } catch (R2CommandException e) {
      throw e;
    } catch (Exception e) {
      throw new R2CommandException("Project " + action + " failed: " + e.getMessage());
    }
  }

  @Override
  public String getHelp() {
    return "Usage: prj load|save <file>\n"
        + " prj load <file> - merge a binary radare2 project into the current program\n"
        + " prj save <file> - export the current program as an RPRJ v6 project\n"
        + " Po <file>       - alias for prj load\n"
        + " Ps <file>       - alias for prj save\n"
        + " Quote paths containing spaces. $files work in memory; disk access follows"
        + " cfg.sandbox and cfg.sandbox.grain.\n";
  }
}
