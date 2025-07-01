package ghidrar2web.repl.handlers;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidrar2web.repl.R2Command;
import ghidrar2web.repl.R2CommandException;
import ghidrar2web.repl.R2CommandHandler;
import ghidrar2web.repl.R2Context;
import ghidrar2web.repl.num.R2NumException;
import ghidrar2web.repl.num.R2NumUtil;

/**
 * Handler for the 'p' (print) command family
 */
public class R2PrintCommandHandler implements R2CommandHandler {

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if it's a 'p' command
        if (!command.hasPrefix("p")) {
            throw new R2CommandException("Not a print command");
        }

        // Get the subcommand without suffix
        String subcommand = command.getSubcommandWithoutSuffix();
        
        // Handle different subcommands
        switch (subcommand) {
            case "8":
                return executeP8Command(command, context);
            case "d":
                return executePdCommand(command, context);
            default:
                throw new R2CommandException("Unknown print subcommand: p" + subcommand);
        }
    }
    
    /**
     * Execute the p8 command to print hexadecimal bytes
     */
    private String executeP8Command(R2Command command, R2Context context) throws R2CommandException {
        // Parse the count argument using RNum
        int count;
        try {
            String countArg = command.getFirstArgument("16");  // Default to 16 bytes
            long numValue = R2NumUtil.evaluateExpression(context, countArg);
            count = (int) numValue;
            if (count <= 0) {
                throw new R2CommandException("Invalid byte count: " + count);
            }
        } catch (R2NumException e) {
            throw new R2CommandException("Invalid count expression: " + e.getMessage());
        }

        // Get the current address
        Address address = context.getCurrentAddress();
        if (address == null) {
            throw new R2CommandException("Current address is not set");
        }
        
        try {
            // Read bytes from memory
            byte[] bytes = context.getAPI().getBytes(address, count);
            
            // Format output based on suffix
            if (command.hasSuffix('j')) {
                return formatP8Json(bytes);
            } else {
                return formatP8Text(bytes);
            }
        } catch (Exception e) {
            throw new R2CommandException("Error reading memory: " + e.getMessage());
        }
    }
    
    /**
     * Format bytes as a hexadecimal string
     */
    private String formatP8Text(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString() + "\n";
    }
    
    /**
     * Format bytes as a JSON array
     */
    private String formatP8Json(byte[] bytes) {
        JSONArray array = new JSONArray();
        for (byte b : bytes) {
            array.put(b & 0xFF);
        }
        return array.toString() + "\n";
    }
    
    /**
     * Execute the pd command to print disassembly
     */
    private String executePdCommand(R2Command command, R2Context context) throws R2CommandException {
        // Parse the count argument using RNum
        int count;
        try {
            String countArg = command.getFirstArgument("10");  // Default to 10 instructions
            long numValue = R2NumUtil.evaluateExpression(context, countArg);
            count = (int) numValue;
            if (count <= 0) {
                throw new R2CommandException("Invalid instruction count: " + count);
            }
        } catch (R2NumException e) {
            throw new R2CommandException("Invalid count expression: " + e.getMessage());
        }

        // Get the current address
        Address address = context.getCurrentAddress();
        if (address == null) {
            throw new R2CommandException("Current address is not set");
        }
        
        boolean showBytes = context.getEvalConfig().getBoolean("asm.bytes");
        
        try {
            // Get the listing
            Listing listing = context.getAPI().getCurrentProgram().getListing();
            SymbolTable symbolTable = context.getAPI().getCurrentProgram().getSymbolTable();
            
            // Get instructions starting from the current address
            List<DisassembledInstruction> instructions = new ArrayList<>();
            Address currentAddr = address;
            
            for (int i = 0; i < count && currentAddr != null; i++) {
                Instruction instr = listing.getInstructionAt(currentAddr);
                if (instr == null) {
                    // No more instructions
                    break;
                }
                
                // Get symbol at this address
                Symbol[] symbols = symbolTable.getSymbols(currentAddr);
                String label = null;
                if (symbols.length > 0) {
                    for (Symbol sym : symbols) {
                        // Prefer function symbols
                        if (sym.getSymbolType() == SymbolType.FUNCTION) {
                            label = sym.getName();
                            break;
                        }
                    }
                    if (label == null) {
                        // If no function symbol, use the first one
                        label = symbols[0].getName();
                    }
                }
                
                // Get instruction bytes
                byte[] bytes = instr.getBytes();
                
                // Get instruction text
                String disasm = instr.toString();
                
                // Create disassembled instruction
                DisassembledInstruction disasmInstr = new DisassembledInstruction();
                disasmInstr.address = currentAddr.getOffset();
                disasmInstr.size = instr.getLength();
                disasmInstr.bytes = bytes;
                disasmInstr.disasm = disasm;
                disasmInstr.label = label;
                
                instructions.add(disasmInstr);
                
                // Move to next instruction
                currentAddr = instr.getMaxAddress().next();
            }
            
            // Format output based on suffix
            if (command.hasSuffix('j')) {
                return formatPdJson(instructions);
            } else {
                return formatPdText(instructions, showBytes);
            }
        } catch (Exception e) {
            throw new R2CommandException("Error disassembling: " + e.getMessage());
        }
    }
    
    /**
     * Format disassembled instructions as text
     */
    private String formatPdText(List<DisassembledInstruction> instructions, boolean showBytes) {
        StringBuilder sb = new StringBuilder();
        
        for (DisassembledInstruction instr : instructions) {
            // Add label if present
            if (instr.label != null) {
                sb.append(instr.label).append(":\n");
            }
            
            // Format address
            sb.append(String.format("  0x%08x      ", instr.address));
            
            // Add bytes if requested
            if (showBytes) {
                sb.append(bytesToHex(instr.bytes));
                // Pad with spaces to align instructions
                int bytesWidth = 20;  // Fixed width for bytes
                int bytesLen = instr.bytes.length * 2;
                for (int i = bytesLen; i < bytesWidth; i++) {
                    sb.append(" ");
                }
            }
            
            // Add disassembly
            sb.append(instr.disasm).append("\n");
        }
        
        return sb.toString();
    }
    
    /**
     * Format disassembled instructions as JSON
     */
    private String formatPdJson(List<DisassembledInstruction> instructions) {
        JSONArray array = new JSONArray();
        
        for (DisassembledInstruction instr : instructions) {
            JSONObject obj = new JSONObject();
            obj.put("addr", instr.address);
            obj.put("size", instr.size);
            obj.put("disasm", instr.disasm);
            obj.put("bytes", bytesToHex(instr.bytes));
            if (instr.label != null) {
                obj.put("label", instr.label);
            }
            array.put(obj);
        }
        
        return array.toString() + "\n";
    }
    
    /**
     * Convert bytes to a hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
    
    /**
     * Class to hold disassembled instruction data
     */
    private static class DisassembledInstruction {
        long address;
        int size;
        byte[] bytes;
        String disasm;
        String label;
    }

    @Override
    public String getHelp() {
        StringBuilder help = new StringBuilder();
        help.append("Usage: p[8|d][j] [count]\n");
        help.append(" p8 [len]     print hexadecimal bytes\n");
        help.append(" p8j [len]    print hexadecimal bytes as json array\n");
        help.append(" pd [n]       print disassembly with n instructions\n");
        help.append(" pdj [n]      print disassembly as json\n");
        help.append("\nExamples:\n");
        help.append(" p8 16        print 16 bytes in hex\n");
        help.append(" p8 0x10      print 16 bytes in hex (using hex number)\n");
        help.append(" p8j 4        print 4 bytes as json array\n");
        help.append(" pd           print 10 disassembled instructions\n");
        help.append(" pd 20        print 20 disassembled instructions\n");
        help.append(" pdj 5        print 5 disassembled instructions as json\n");
        return help.toString();
    }
}
