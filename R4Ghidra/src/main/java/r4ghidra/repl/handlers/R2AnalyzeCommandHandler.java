package r4ghidra.repl.handlers;

import java.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;

/**
 * Handler for the 'a' (analyze) command family: af (analyze function), afl (list functions), afi (function info)
 */
public class R2AnalyzeCommandHandler implements R2CommandHandler {

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        if (!command.hasPrefix("a")) {
            throw new R2CommandException("Not an analyze command");
        }
        String sub = command.getSubcommandWithoutSuffix();
        switch (sub) {
            case "f":
                return handleAf(command, context);
            case "fl":
                return handleAfl(command, context);
            case "fi":
                return handleAfi(command, context);
            default:
                throw new R2CommandException("Unknown analyze subcommand: a" + sub);
        }
    }

    // Analyze current function (create/disassemble) and show info
    private String handleAf(R2Command command, R2Context context) throws R2CommandException {
        Address addr = context.getCurrentAddress();
        if (addr == null) {
            throw new R2CommandException("Current address is not set");
        }
        FlatProgramAPI api = context.getAPI();
        // Disassemble and create function at current address
        api.disassemble(addr);
        try {
            api.createFunction(addr, "ghidra." + context.formatAddress(addr));
        } catch (Exception e) {
            // ignore if function already exists or creation failed
        }
        // After analysis, show function info
        return handleAfi(command, context);
    }

    // List all functions in program
    private String handleAfl(R2Command command, R2Context context) throws R2CommandException {
        FlatProgramAPI api = context.getAPI();
        Function f = api.getFirstFunction();
        boolean json = command.hasSuffix('j');
        boolean rad = command.hasSuffix('*');
        if (json) {
            JSONArray arr = new JSONArray();
            while (f != null) {
                JSONObject obj = new JSONObject();
                obj.put("name", f.getName());
                obj.put("offset", f.getEntryPoint().getOffset());
                arr.put(obj);
                f = api.getFunctionAfter(f);
            }
            return arr.toString() + "\n";
        } else {
            StringBuilder sb = new StringBuilder();
            while (f != null) {
                if (rad) {
                    sb.append("f ghidra.").append(f.getName())
                      .append(" 1 ").append(context.formatAddress(f.getEntryPoint()))
                      .append("\n");
                } else {
                    sb.append(context.formatAddress(f.getEntryPoint()))
                      .append("  ")
                      .append(f.getName())
                      .append("\n");
                }
                f = api.getFunctionAfter(f);
            }
            return sb.toString();
        }
    }

    // Show info for current function (variables, comment)
    private String handleAfi(R2Command command, R2Context context) throws R2CommandException {
        FlatProgramAPI api = context.getAPI();
        Address addr = context.getCurrentAddress();
        if (addr == null) {
            throw new R2CommandException("Current address is not set");
        }
        Function f = api.getFunctionContaining(addr);
        if (f == null) {
            throw new R2CommandException("Cannot find function at " + context.formatAddress(addr));
        }
        try {
            // Gather variables and comment
            Variable[] vars = f.getAllVariables();
            String comment = f.getComment();
            StringBuilder sb = new StringBuilder();
            // Function entry
            sb.append("Function: ").append(f.getName())
              .append(" @ ").append(context.formatAddress(f.getEntryPoint()))
              .append("\n");
            // Parameters and locals
            for (Variable v : vars) {
                sb.append(v.getName())
                  .append(" : ")
                  .append(v.getDataType().getName())
                  .append(" @ offset ")
                  .append(v.getStackOffset())
                  .append("\n");
            }
            // Comment (base64-encoded)
            if (comment != null && !comment.isEmpty()) {
                String b64 = Base64.getEncoder().encodeToString(comment.getBytes());
                sb.append("CCu base64:").append(b64)
                  .append(" @ ").append(context.formatAddress(f.getEntryPoint()))
                  .append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            throw new R2CommandException(e.getMessage());
        }
    }

    @Override
    public String getHelp() {
        StringBuilder help = new StringBuilder();
        help.append("Usage: a[f|fl|fi][j*] [args]\n");
        help.append(" af            analyze function at current offset\n");
        help.append(" afl           list functions\n");
        help.append(" afl*          list as r2 commands\n");
        help.append(" afl j         list functions as JSON\n");
        help.append(" afi           show info for current function\n");
        help.append(" afi j         show function info as JSON (not implemented)\n");
        return help.toString();
    }
}