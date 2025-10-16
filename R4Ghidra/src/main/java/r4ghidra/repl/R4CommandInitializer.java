package r4ghidra.repl;

import r4ghidra.repl.handlers.*;

import java.util.ArrayList;
import java.util.List;

public class R4CommandInitializer {

    private static List<R2CommandHandler> commandHandlers=null;


    /** Initialize all command handlers for R4Ghidra */
    public static List<R2CommandHandler> getCommandHandlers() {
        if (commandHandlers != null){
            return commandHandlers;
        }
        commandHandlers=new ArrayList<R2CommandHandler>();
        // Register all command handlers
        commandHandlers.add(new R2SeekCommandHandler());
        commandHandlers.add(new R2PrintCommandHandler());
        // Register the print command handler again with 'x' prefix as an alias for 'px'
        commandHandlers.add(
                new R2PrintCommandHandler() {
                    @Override
                    public String execute(r4ghidra.repl.R2Command command, r4ghidra.repl.R2Context context)
                            throws r4ghidra.repl.R2CommandException {
                        // Modify the command to prefix with 'p' to make it look like 'px'
                        r4ghidra.repl.R2Command modifiedCommand =
                                new r4ghidra.repl.R2Command(
                                        "p", // Change prefix to 'p'
                                        "x" + command.getSubcommand(), // Prefix subcommand with 'x'
                                        command.getArguments(), // Keep original arguments
                                        command.getTemporaryAddress() // Keep original temporary address
                                );
                        // Execute the modified command through the regular handler
                        return super.execute(modifiedCommand, context);
                    }

                    @Override
                    public String getHelp() {
                        // Return a modified help string that includes the 'x' command
                        StringBuilder help = new StringBuilder();
                        help.append("Usage: x[j] [count]\n");
                        help.append(" x [len]      print hexdump (alias for px)\n");
                        help.append(" xj [len]     print hexdump as json (alias for pxj)\n");
                        help.append("\nExamples:\n");
                        help.append(" x            print hexdump using default block size\n");
                        help.append(" x 32         print 32 bytes hexdump\n");
                        help.append(" xj 16        print 16 bytes hexdump as json\n");
                        return help.toString();
                    }
                });
        commandHandlers.add(new R2BlocksizeCommandHandler());
        // commandHandlers.add(new R2DecompileCommandHandler());
        commandHandlers.add(new R2EnvCommandHandler());
        commandHandlers.add(new R2EvalCommandHandler());
        commandHandlers.add(new R2ShellCommandHandler());
        // Analyze commands: af, afl, afi
        commandHandlers.add(new R2AnalyzeCommandHandler());
        commandHandlers.add(new R2InfoCommandHandler());
        commandHandlers.add(new R2CommentCommandHandler());
        commandHandlers.add(new R2FlagCommandHandler());
        commandHandlers.add(new R2QuitCommandHandler());
        commandHandlers.add(new R2ClearCommandHandler());

        return commandHandlers;
        // Note: R2HelpCommandHandler will be created in the CommandShellProvider
        // because it needs a reference to the command registry

        // Add more handlers as needed
    }
}
