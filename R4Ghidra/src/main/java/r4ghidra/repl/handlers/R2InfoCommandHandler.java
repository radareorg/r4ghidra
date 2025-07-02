package r4ghidra.repl.handlers;

import org.json.JSONObject;

import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;

/**
 * Handler for the 'i' (info) command family
 * 
 * This command provides information about the program and its architecture.
 */
public class R2InfoCommandHandler implements R2CommandHandler {

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if it's an 'i' command
        if (!command.hasPrefix("i")) {
            throw new R2CommandException("Not an info command");
        }

        // Get the subcommand without suffix
        String subcommand = command.getSubcommandWithoutSuffix();
        
        // Handle different subcommands or default to basic info
        if (subcommand.isEmpty()) {
            return executeBasicInfoCommand(command, context);
        } else {
            switch (subcommand) {
                default:
                    return executeBasicInfoCommand(command, context);
            }
        }
    }
    
    /**
     * Execute the basic info command to show program information
     */
    private String executeBasicInfoCommand(R2Command command, R2Context context) throws R2CommandException {
            Program program = context.getAPI().getCurrentProgram();
            if (program == null) {
                throw new R2CommandException("No program is loaded");
            }
            
            Language language = program.getLanguage();
            String processor = language.getProcessor().toString().toLowerCase();
            
            // Determine architecture and bits
            String arch = "x86";
            String bits = "64";
            
            if (processor.equals("aarch64")) {
                arch = "arm";
                bits = "64";
            } else if (processor.contains("arm")) {
                arch = "arm";
                bits = "32";
            } else if (processor.contains("mips")) {
                arch = "mips";
                bits = language.getDefaultSpace().getSize() == 64 ? "64" : "32";
            } else if (processor.contains("ppc") || processor.contains("powerpc")) {
                arch = "ppc";
                bits = language.getDefaultSpace().getSize() == 64 ? "64" : "32";
            } else if (processor.contains("x86")) {
                arch = "x86";
                bits = language.getDefaultSpace().getSize() == 64 ? "64" : "32";
            } else if (processor.contains("sparc")) {
                arch = "sparc";
                bits = language.getDefaultSpace().getSize() == 64 ? "64" : "32";
            } else if (processor.contains("avr")) {
                arch = "avr";
                bits = "8";
            } else if (processor.contains("6502")) {
                arch = "6502";
                bits = "8";
            } else if (processor.contains("z80")) {
                arch = "z80";
                bits = "8";
            }
            
            // Format output based on suffix
            if (command.hasSuffix('j')) {
                return formatInfoJson(program, arch, bits, processor);
            } else {
                return formatInfoText(program, arch, bits, processor);
            }
    }
    
    /**
     * Format program information as text
     */
    private String formatInfoText(Program program, String arch, String bits, String processor) {
        StringBuilder sb = new StringBuilder();
        
        // Output the r2 commands that would set up the environment
        sb.append("e asm.arch=").append(arch).append("\n");
        sb.append("e asm.bits=").append(bits).append("\n");
        sb.append("f base.addr=0x").append(program.getImageBase()).append("\n");
        
        // Add additional information as comments
        sb.append("# cpu ").append(processor).append("\n");
        sb.append("# md5 ").append(program.getExecutableMD5()).append("\n");
        sb.append("# exe ").append(program.getExecutablePath()).append("\n");
        
        // Add language information
        sb.append("# language ").append(program.getLanguage().getLanguageID().getIdAsString()).append("\n");
        sb.append("# compiler ").append(program.getCompiler()).append("\n");
        
        // Add program size
        sb.append("# size ").append(program.getMaxAddress().subtract(program.getMinAddress()) + 1).append("\n");
        
        return sb.toString();
    }
    
    /**
     * Format program information as JSON
     */
    private String formatInfoJson(Program program, String arch, String bits, String processor) {
        JSONObject info = new JSONObject();
        
        // Basic architecture info
        info.put("arch", arch);
        info.put("bits", Integer.parseInt(bits));
        info.put("base", "0x" + Long.toHexString(program.getImageBase().getOffset()));
        
        // CPU and other information
        info.put("cpu", processor);
        info.put("md5", program.getExecutableMD5());
        info.put("file", program.getExecutablePath());
        info.put("language", program.getLanguage().getLanguageID().getIdAsString());
        info.put("compiler", program.getCompiler());
        info.put("size", program.getMaxAddress().subtract(program.getMinAddress()) + 1);
        
        return info.toString(2) + "\n";
    }

    @Override
    public String getHelp() {
        StringBuilder help = new StringBuilder();
        help.append("Usage: i[j] - Show program information\n\n");
        help.append("i       Show basic program information\n");
        help.append("ij      Show program information as JSON\n");
        help.append("\nExamples:\n");
        help.append("i       Display basic program information\n");
        help.append("ij      Display program information as JSON\n");
        return help.toString();
    }
}
