package r4ghidra.repl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import r4ghidra.repl.filesystem.R2FileSystemException;

/**
 * Radare2 REPL Implementation
 * 
 * This class provides a complete implementation of the radare2 REPL (Read-Eval-Print Loop)
 * with support for command parsing, execution, and special syntax handling.
 */
public class R2REPLImpl {
    
    // Singleton instance for static access
    private static R2REPLImpl instance;
    
    // Root command registry - maps command prefixes to handlers
    private Map<String, R2CommandHandler> commandRegistry;
    
    // Context that can be accessed by command handlers
    private R2Context context;
    
    // Command history storage
    private List<String> commandHistory = new ArrayList<>();
    
    /**
     * Create a new R2 REPL implementation
     */
    public R2REPLImpl() {
        commandRegistry = new HashMap<>();
        context = new R2Context();
        
        // Set the singleton instance
        instance = this;
    }
    
    /**
     * Register a new command handler
     * 
     * @param prefix The command prefix (e.g., "s" for seek)
     * @param handler The handler implementation
     */
    public void registerCommand(String prefix, R2CommandHandler handler) {
        // Simply register the command handler
        commandRegistry.put(prefix, handler);
    }
    
    /**
     * Parse and execute a command string
     * 
     * @param cmdStr The command string to execute
     * @return The result of the command execution
     */
    public String executeCommand(String cmdStr) {
        if (cmdStr == null || cmdStr.trim().isEmpty()) {
            return "";
        }
        
        // Special case: if command starts with #, it's a comment-only command
        // and should be treated as empty
        if (cmdStr.trim().startsWith("#")) {
            return "";
        }
        
        // Add command to history
        addToHistory(cmdStr);
        
        try {
            // Check for semicolon-separated commands
            int semicolonIndex = findUnquotedChar(cmdStr, ';');
            if (semicolonIndex > 0) {
                return executeSemicolonSeparatedCommands(cmdStr);
            }
            
            // Check for append redirection (>>)
            int appendIndex = findUnquotedString(cmdStr, ">>");
            if (appendIndex > 0) {
                return executeRedirectCommand(cmdStr, appendIndex, true);
            }
            
            // Check for output redirection (>)
            int redirectIndex = findUnquotedChar(cmdStr, '>');
            if (redirectIndex > 0) {
                // Check for comments in the redirection command
                int commentIndex = findUnquotedChar(cmdStr, '#');
                if (commentIndex > 0 && commentIndex < redirectIndex) {
                    // Comment is before redirection, truncate the command
                    cmdStr = cmdStr.substring(0, commentIndex).trim();
                    // Re-check if we still have redirection after comment removal
                    redirectIndex = findUnquotedChar(cmdStr, '>');
                    if (redirectIndex <= 0) {
                        return executeCommand(cmdStr);
                    }
                }
                return executeRedirectCommand(cmdStr, redirectIndex, false);
            }
            
            // Check for pipe operator (|)
            int pipeIndex = findUnquotedChar(cmdStr, '|');
            if (pipeIndex > 0) {
                // Check for comments in the piped command
                int commentIndex = findUnquotedChar(cmdStr, '#');
                if (commentIndex > 0 && commentIndex < pipeIndex) {
                    // Comment is before pipe, truncate the command
                    cmdStr = cmdStr.substring(0, commentIndex).trim();
                    // Re-check if we still have a pipe after comment removal
                    pipeIndex = findUnquotedChar(cmdStr, '|');
                    if (pipeIndex <= 0) {
                        return executeCommand(cmdStr);
                    }
                }
                return executePipeCommand(cmdStr, pipeIndex);
            }
            
            // Check for output filter (~)
            // First check for comments and remove them before processing filters
            int commentIndex = findUnquotedChar(cmdStr, '#');
            if (commentIndex > 0) {
                cmdStr = cmdStr.substring(0, commentIndex).trim();
            }
            
            String[] cmdAndFilter = R2OutputFilter.extractCommandAndFilter(cmdStr);
            if (cmdAndFilter != null) {
                String cmd = cmdAndFilter[0];
                String filter = cmdAndFilter[1];
                boolean useAndLogic = Boolean.parseBoolean(cmdAndFilter[2]);
                String columns = cmdAndFilter.length > 3 ? cmdAndFilter[3] : null;
                boolean useNegationLogic = cmdAndFilter.length > 4 ? Boolean.parseBoolean(cmdAndFilter[4]) : false;
                
                // Special case for help command
                if (cmd.isEmpty() && filter.equals("?")) {
                    return R2OutputFilter.getFilterHelp();
                }
                
                // Execute the command and apply the filter
                String result = executeCommand(cmd);
                return R2OutputFilter.applyFilter(result, filter, useAndLogic, columns, useNegationLogic);
            }
            
            // Handle special case for dot commands (.)
            if (cmdStr.startsWith(".")) {
                return executeDotCommand(cmdStr);
            }
            
            // Handle special case for quoted commands (')
            if (cmdStr.startsWith("'")) {
                // Check if it's a temporary seek with '0x syntax
                if (cmdStr.startsWith("'0x")) {
                    return executeTemporarySeekCommand(cmdStr);
                }
                return executeQuotedCommand(cmdStr);
            }
            
            // Parse the command
            R2Command cmd = parseCommand(cmdStr);
            // If the suffix is '?', show help for this command prefix
            if (cmd.getCommandSuffix().charValue() == '?') {
                R2CommandHandler helpHandler = commandRegistry.get(cmd.getPrefix());
                if (helpHandler != null) {
                    return helpHandler.getHelp();
                }
                // If no specific handler, show general help for all commands
                StringBuilder allHelp = new StringBuilder();
                for (R2CommandHandler h : commandRegistry.values()) {
                    allHelp.append(h.getHelp()).append("\n");
                }
                return allHelp.toString();
            }
            
            // Handle @@ syntax for multiple command execution
            if (cmd.hasMultiAddressInfo()) {
                return executeMultiAddressCommand(cmd);
            }
            
            // Handle special @ syntax for temporary seek
            Address originalSeek = null;
            if (cmd.hasTemporaryAddress()) {
                originalSeek = context.getCurrentAddress();
                context.setCurrentAddress(cmd.getTemporaryAddress());
            }
            
            // Find and execute the handler
            String result = executeCommandWithHandler(cmd);
            
            // Restore original seek position if we had a temporary seek
            if (cmd.hasTemporaryAddress() && context.getCurrentAddress().equals(cmd.getTemporaryAddress())) {
                context.setCurrentAddress(originalSeek);
            }
            
            return result;
        } catch (R2CommandException e) {
            return "Error: " + e.getMessage();
        }
    }
    
    /**
     * Execute a dot command (.) that either:
     * 1. Runs a command and then processes its output as r2 commands, or
     * 2. Reads a script file and executes each line as an r2 command, or
     * 3. Executes a shell command and processes its output as r2 commands
     * 
     * @param dotCmdStr The dot command string
     * @return The combined result of executing all resulting commands
     */
    private String executeDotCommand(String dotCmdStr) throws R2CommandException {
        // Remove the leading dot
        String cmdStr = dotCmdStr.substring(1).trim();
        
        if (cmdStr.isEmpty()) {
            throw new R2CommandException("Empty dot command");
        }
        
        // Check if we're loading a script file (when command starts with a space)
        if (cmdStr.startsWith(" ")) {
            String filePath = cmdStr.trim();
            return executeScriptFile(filePath);
        } 
        // Check if we're executing a shell command (when command starts with !)
        else if (cmdStr.startsWith("!")) {
            String shellCmd = cmdStr.substring(1).trim();
            return executeShellCommandAsScript(shellCmd);
        } 
        else {
            // Original behavior: execute command and process its output
            String cmdOutput = executeCommand(cmdStr);
            return executeScriptFromOutput(cmdOutput);
        }
    }
    
    /**
     * Execute r2 commands from a script file
     * 
     * @param filePath The path to the script file
     * @return The combined result of executing all commands in the file
     */
    private String executeScriptFile(String filePath) throws R2CommandException {
        try {
            // Read the script file
            java.nio.file.Path path = java.nio.file.Paths.get(filePath);
            if (!java.nio.file.Files.exists(path)) {
                throw new R2CommandException("Script file not found: " + filePath);
            }
            
            String scriptContent = new String(java.nio.file.Files.readAllBytes(path));
            return executeScriptFromOutput(scriptContent);
            
        } catch (java.io.IOException e) {
            throw new R2CommandException("Error reading script file: " + e.getMessage());
        }
    }
    
    /**
     * Execute a shell command and interpret its output as an r2 script
     * 
     * @param shellCmd The shell command to execute
     * @return The combined result of executing the command output as r2 commands
     */
    private String executeShellCommandAsScript(String shellCmd) throws R2CommandException {
        if (shellCmd.isEmpty()) {
            throw new R2CommandException("Empty shell command");
        }
        
        // Get the shell command handler
        R2CommandHandler shellHandler = commandRegistry.get("!");
        if (shellHandler == null) {
            throw new R2CommandException("Shell command handler not registered");
        }
        
        // Create a command for the shell handler with !! prefix to ensure output capture
        // We prefix with another ! to ensure the command is processed as !! by the handler
        List<String> args = new ArrayList<>();
        R2Command shellCommand = new R2Command("!", "!" + shellCmd, args, null);
        
        // Execute the shell command to get its output
        String shellOutput = shellHandler.execute(shellCommand, context);
        
        // Process the shell output as an r2 script
        return executeScriptFromOutput(shellOutput);
    }
    
    /**
     * Execute a series of r2 commands from text content
     * 
     * @param scriptContent The text containing commands, one per line
     * @return The combined result of executing all commands
     */
    private String executeScriptFromOutput(String scriptContent) throws R2CommandException {
        // Process the output as a series of r2 commands
        StringBuilder result = new StringBuilder();
        
        // Split by lines and execute each line as a separate command
        String[] lines = scriptContent.split("\\n");
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty()) {
                // Execute the command and append its output to the result
                try {
                    String lineResult = executeCommand(line);
                    if (lineResult != null && !lineResult.isEmpty()) {
                        result.append(lineResult);
                        // Add a newline if one isn't already present
                        if (!lineResult.endsWith("\n")) {
                            result.append("\n");
                        }
                    }
                } catch (Exception e) {
                    // Log the error but continue processing other lines
                    result.append("Error executing command '")
                          .append(line)
                          .append("': ")
                          .append(e.getMessage())
                          .append("\n");
                }
            }
        }
        
        return result.toString();
    }
    
    /**
     * Execute a command with temporary seek using '0x syntax.
     * This is equivalent to the @ syntax but with no special character interpretation.
     * Example: '0x80'pd 4 is equivalent to pd 4 @ 0x80
     * 
     * @param cmdStr The command string starting with '0x
     * @return The result of the command execution
     */
    private String executeTemporarySeekCommand(String cmdStr) throws R2CommandException {
        // Find the closing single quote that separates the address from the command
        int closingQuotePos = cmdStr.indexOf("'", 1);
        if (closingQuotePos == -1) {
            throw new R2CommandException("Missing closing quote in '0x temporary seek syntax");
        }
        
        // Extract the address (between '0x and ')
        String addressStr = cmdStr.substring(1, closingQuotePos); // without the quotes
        
        // Extract the command part (after the second quote)
        String commandStr = cmdStr.substring(closingQuotePos + 1);
        
        if (commandStr.isEmpty()) {
            throw new R2CommandException("Empty command in temporary seek");
        }
        
        // Parse the address
        Address address;
        try {
            address = context.parseAddress(addressStr);
        } catch (Exception e) {
            throw new R2CommandException("Invalid address in temporary seek: " + addressStr);
        }
        
        // Store the original address
        Address originalAddress = context.getCurrentAddress();
        
        try {
            // Set the temporary address
            context.setCurrentAddress(address);
            
            // Execute the command as a quoted command (no special character interpretation)
            R2Command cmd = parseCommandLiteral(commandStr);
            return executeCommandWithHandler(cmd);
        } finally {
            // Restore the original address
            context.setCurrentAddress(originalAddress);
        }
    }
    
    /**
     * Parse a command string literally, without interpreting special characters
     * 
     * @param cmdStr The command string to parse
     * @return A parsed R2Command object
     */
    private R2Command parseCommandLiteral(String cmdStr) throws R2CommandException {
        if (cmdStr.isEmpty()) {
            throw new R2CommandException("Empty command");
        }
        
        String prefix = String.valueOf(cmdStr.charAt(0));
        String subcommand = cmdStr.length() > 1 ? cmdStr.substring(1) : "";
        
        List<String> args = new ArrayList<>();
        
        // Parse arguments based on spaces, without any special character processing
        if (subcommand.contains(" ")) {
            int spacePos = subcommand.indexOf(" ");
            String argsPart = subcommand.substring(spacePos).trim();
            subcommand = subcommand.substring(0, spacePos);
            
            // Simple space-separated args, no processing of special chars
            String[] argArray = argsPart.split("\\s+");
            for (String arg : argArray) {
                if (!arg.trim().isEmpty()) {
                    args.add(arg.trim());
                }
            }
        }
        
        return new R2Command(prefix, subcommand, args, null);
    }
    
    /**
     * Execute a command that starts with a single quote.
     * This will process the command as a literal string without interpreting special characters.
     * According to the requirement, if a command starts with a single quote, any semicolons after that
     * will be ignored (not treated as command separators).
     * 
     * @param quotedStr The quoted command string
     * @return The result of the command execution
     */
    private String executeQuotedCommand(String quotedStr) throws R2CommandException {
        // Remove the leading single quote
        String cmdStr = quotedStr.substring(1);
        
        // Create a command object directly, no special character processing
        if (cmdStr.isEmpty()) {
            throw new R2CommandException("Empty quoted command");
        }
        
        // If there are semicolons in the quoted command, they are treated as regular characters
        // and not as command separators - this is handled because we're executing this command directly
        // without passing it back through executeCommand
        
        String prefix = String.valueOf(cmdStr.charAt(0));
        String subcommand = cmdStr.length() > 1 ? cmdStr.substring(1) : "";
        
        List<String> args = new ArrayList<>();
        
        // Parse arguments based on spaces, without any special character processing
        if (subcommand.contains(" ")) {
            int spacePos = subcommand.indexOf(" ");
            String argsPart = subcommand.substring(spacePos).trim();
            subcommand = subcommand.substring(0, spacePos);
            
            // Simple space-separated args, no processing of quotes or other special chars
            String[] argArray = argsPart.split("\\s+");
            for (String arg : argArray) {
                if (!arg.trim().isEmpty()) {
                    args.add(arg.trim());
                }
            }
        }
        
        // No temporary address or command substitution for quoted commands
        R2Command cmd = new R2Command(prefix, subcommand, args, null);
        
        // Execute the command directly
        return executeCommandWithHandler(cmd);
    }
    
    /**
     * Find and execute the appropriate handler for a parsed command
     */
    private String executeCommandWithHandler(R2Command cmd) throws R2CommandException {
        String prefix = cmd.getPrefix();
        R2CommandHandler handler = commandRegistry.get(prefix);
        
        if (handler == null) {
            throw new R2CommandException("Unknown command: " + prefix);
        }
        
        return handler.execute(cmd, context);
    }
    
    /**
     * Process any comments in the command string (# character)
     * If the command starts with a single quote, preserve the # character
     * Otherwise, trim everything after the # character
     * 
     * @param cmdStr The command string to process
     * @return The command string with comments processed
     */
    private String processComments(String cmdStr) {
        if (cmdStr == null || cmdStr.isEmpty()) {
            return cmdStr;
        }
        
        // If the command starts with a single quote, don't process comments
        if (cmdStr.startsWith("'")) {
            return cmdStr;
        }
        
        // Find the first unquoted # character
        int commentIndex = findUnquotedChar(cmdStr, '#');
        if (commentIndex >= 0) {
            return cmdStr.substring(0, commentIndex).trim();
        }
        
        return cmdStr;
    }

    /**
     * Parse a command string into an R2Command object
     */
    private R2Command parseCommand(String cmdStr) throws R2CommandException {
        // Process comments first
        cmdStr = processComments(cmdStr);
        
        // Extract any backtick command substitution
        cmdStr = processCommandSubstitution(cmdStr);
        
        // Check for @@ command (multiple command execution)
        if (cmdStr.contains("@@")) {
            return parseMultiAddressCommand(cmdStr);
        }
        
        // Split the command into the main part and any @ address part
        String[] atParts = cmdStr.split("@", 2);
        
        String mainCommand = atParts[0].trim();
        Address tempAddress = null;
        
        // If we have an @ part, parse the address
        if (atParts.length > 1) {
            String addrStr = atParts[1].trim();
            try {
                tempAddress = context.parseAddress(addrStr);
            } catch (Exception e) {
                throw new R2CommandException("Invalid address: " + addrStr);
            }
        }
        
        // Parse the main command into prefix, subcommands, and arguments
        if (mainCommand.isEmpty()) {
            throw new R2CommandException("Empty command");
        }
        
        String prefix = String.valueOf(mainCommand.charAt(0));
        String subcommand = mainCommand.length() > 1 ? mainCommand.substring(1) : "";
        
        List<String> args = new ArrayList<>();
        
        // Parse arguments based on spaces, but respect quoted strings
        if (subcommand.contains(" ")) {
            int spacePos = subcommand.indexOf(" ");
            String argsPart = subcommand.substring(spacePos).trim();
            subcommand = subcommand.substring(0, spacePos);
            
            // Parse arguments with proper handling of quoted strings
            Pattern pattern = Pattern.compile("[^\\s\"']+|\"([^\"]*)\"|'([^']*)'");
            Matcher matcher = pattern.matcher(argsPart);
            
            while (matcher.find()) {
                if (matcher.group(1) != null) {
                    // Add double-quoted string without quotes
                    args.add(matcher.group(1));
                } else if (matcher.group(2) != null) {
                    // Add single-quoted string without quotes
                    args.add(matcher.group(2));
                } else {
                    // Add unquoted word
                    args.add(matcher.group());
                }
            }
        }
        
        return new R2Command(prefix, subcommand, args, tempAddress);
    }
    
    /**
     * Process any command substitution using backticks
     */
    private String processCommandSubstitution(String cmdStr) throws R2CommandException {
        // Find all backtick-enclosed content
        Pattern pattern = Pattern.compile("`([^`]*)`");
        Matcher matcher = pattern.matcher(cmdStr);
        StringBuffer result = new StringBuffer();
        
        while (matcher.find()) {
            String innerCommand = matcher.group(1);
            String innerResult = executeCommand(innerCommand).trim();
            matcher.appendReplacement(result, Matcher.quoteReplacement(innerResult));
        }
        
        matcher.appendTail(result);
        return result.toString();
    }
    
    /**
     * Execute multiple commands separated by semicolons
     * 
     * @param cmdStr The command string containing semicolon-separated commands
     * @return The combined result of all commands
     */
    private String executeSemicolonSeparatedCommands(String cmdStr) throws R2CommandException {
        StringBuilder result = new StringBuilder();
        
        // Split the command string by semicolons, respecting quotes
        String[] commands = splitBySemicolon(cmdStr);
        
        // Execute each command and combine the results
        for (String cmd : commands) {
            String trimmedCmd = cmd.trim();
            if (!trimmedCmd.isEmpty()) {
                // Each command should be processed separately
                String cmdResult = executeCommand(trimmedCmd);
                result.append(cmdResult);
                
                // Add a newline separator between command results if needed
                if (!cmdResult.isEmpty() && !cmdResult.endsWith("\n")) {
                    result.append("\n");
                }
            }
        }
        
        return result.toString();
    }
    
    /**
     * Split a command string by semicolons, respecting quotes and handling the special case
     * where a command starts with a single quote (in which case semicolons are not treated as separators).
     * 
     * @param cmdStr The command string to split
     * @return An array of individual commands
     */
    private String[] splitBySemicolon(String cmdStr) {
        java.util.List<String> commands = new java.util.ArrayList<>();
        
        boolean inSingleQuotes = false;
        boolean inDoubleQuotes = false;
        int lastSplitPos = 0;
        
        for (int i = 0; i < cmdStr.length(); i++) {
            char c = cmdStr.charAt(i);
            
            // Special case: if we see a single quote at the beginning of a command segment,
            // anything after that within this segment will be treated as a literal (no semicolon splitting)
            if (i == lastSplitPos && c == '\'') {
                // Find the next semicolon outside of any quotes (to find the end of this command)
                int nextSemicolon = findUnquotedChar(cmdStr.substring(i), ';');
                if (nextSemicolon == -1) {
                    // No more semicolons, add the rest as a single command
                    commands.add(cmdStr.substring(lastSplitPos));
                    break;
                } else {
                    // Add everything up to the semicolon as one command
                    commands.add(cmdStr.substring(lastSplitPos, i + nextSemicolon));
                    lastSplitPos = i + nextSemicolon + 1;
                    i = lastSplitPos - 1; // Adjust i to resume from the new position
                }
                continue;
            }
            
            // Handle quotes for regular processing
            if (c == '\'' && !inDoubleQuotes) {
                inSingleQuotes = !inSingleQuotes;
            } else if (c == '"' && !inSingleQuotes) {
                inDoubleQuotes = !inDoubleQuotes;
            } 
            // Split on semicolon when not in quotes
            else if (c == ';' && !inSingleQuotes && !inDoubleQuotes) {
                commands.add(cmdStr.substring(lastSplitPos, i));
                lastSplitPos = i + 1;
            }
        }
        
        // Add the last command if there's anything left
        if (lastSplitPos < cmdStr.length()) {
            commands.add(cmdStr.substring(lastSplitPos));
        }
        
        return commands.toArray(new String[0]);
    }
    
    /**
     * Find an unquoted character in a string, respecting quotes
     * 
     * @param str The string to search in
     * @param charToFind The character to find
     * @return The index of the first occurrence of the character outside quotes, or -1 if not found
     */
    private int findUnquotedChar(String str, char charToFind) {
        boolean inSingleQuotes = false;
        boolean inDoubleQuotes = false;
        
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            
            // Handle quotes
            if (c == '\'' && !inDoubleQuotes) {
                inSingleQuotes = !inSingleQuotes;
            } else if (c == '"' && !inSingleQuotes) {
                inDoubleQuotes = !inDoubleQuotes;
            } 
            // Check for character only if not in quotes
            else if (c == charToFind && !inSingleQuotes && !inDoubleQuotes) {
                return i;
            }
        }
        
        return -1; // Not found
    }
    
    /**
     * Find an unquoted string in another string, respecting quotes
     * 
     * @param str The string to search in
     * @param stringToFind The string to find
     * @return The index of the first occurrence of the string outside quotes, or -1 if not found
     */
    private int findUnquotedString(String str, String stringToFind) {
        boolean inSingleQuotes = false;
        boolean inDoubleQuotes = false;
        
        for (int i = 0; i <= str.length() - stringToFind.length(); i++) {
            char c = str.charAt(i);
            
            // Handle quotes
            if (c == '\'' && !inDoubleQuotes) {
                inSingleQuotes = !inSingleQuotes;
            } else if (c == '"' && !inSingleQuotes) {
                inDoubleQuotes = !inDoubleQuotes;
            } 
            // Check for string match only if not in quotes
            else if (!inSingleQuotes && !inDoubleQuotes) {
                boolean matches = true;
                for (int j = 0; j < stringToFind.length(); j++) {
                    if (str.charAt(i + j) != stringToFind.charAt(j)) {
                        matches = false;
                        break;
                    }
                }
                if (matches) {
                    return i;
                }
            }
        }
        
        return -1; // Not found
    }
    
    /**
     * Execute a pipe command (cmd1 | cmd2)
     * 
     * @param cmdStr The full command string with the pipe
     * @param pipeIndex The position of the pipe character
     * @return The result of executing the pipe command
     */
    private String executePipeCommand(String cmdStr, int pipeIndex) throws R2CommandException {
        // Split the command string at the pipe
        String leftCmd = cmdStr.substring(0, pipeIndex).trim();
        String rightCmd = cmdStr.substring(pipeIndex + 1).trim();
        
        if (leftCmd.isEmpty() || rightCmd.isEmpty()) {
            throw new R2CommandException("Empty command in pipe");
        }
        
        // Execute the left command to get its output
        String leftOutput = executeCommand(leftCmd);
        
        try {
            // Create a process for the right command
            ProcessBuilder processBuilder = new ProcessBuilder();
            if (System.getProperty("os.name").toLowerCase().contains("windows")) {
                processBuilder.command("cmd.exe", "/c", rightCmd);
            } else {
                processBuilder.command("bash", "-c", rightCmd);
            }
            
            // Start the process
            Process process = processBuilder.start();
            
            // Write the left command's output to the process's stdin
            try (java.io.OutputStream stdin = process.getOutputStream()) {
                stdin.write(leftOutput.getBytes());
                stdin.flush();
            }
            
            // Read the process's stdout
            StringBuilder output = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            
            // Wait for the process to complete
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                // Read the error stream if there was an error
                StringBuilder errorOutput = new StringBuilder();
                try (java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(process.getErrorStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        errorOutput.append(line).append("\n");
                    }
                }
                
                throw new R2CommandException("Shell command failed with exit code " + exitCode + ": " + errorOutput);
            }
            
            return output.toString();
        } catch (java.io.IOException | InterruptedException e) {
            throw new R2CommandException("Error executing pipe command: " + e.getMessage());
        }
    }
    
    /**
     * Execute a redirection command (cmd > file or cmd >> file)
     * 
     * @param cmdStr The full command string with the redirection
     * @param redirectIndex The position of the redirection operator
     * @param append Whether to append to the file (>> instead of >)
     * @return A message indicating success or failure
     */
    private String executeRedirectCommand(String cmdStr, int redirectIndex, boolean append) throws R2CommandException {
        // Determine the length of the redirection operator (> or >>)
        int operatorLength = append ? 2 : 1;
        
        // Split the command string at the redirection operator
        String leftCmd = cmdStr.substring(0, redirectIndex).trim();
        String filePath = cmdStr.substring(redirectIndex + operatorLength).trim();
        
        if (leftCmd.isEmpty() || filePath.isEmpty()) {
            throw new R2CommandException(append ? "Usage: command >> file" : "Usage: command > file");
        }
        
        // Execute the left command to get its output
        String output = executeCommand(leftCmd);
        
        try {
            // Use the filesystem abstraction for file operations
            if (append) {
                context.getFileSystem().appendFile(filePath, output);
            } else {
                context.getFileSystem().writeFile(filePath, output);
            }
            
            return "Output " + (append ? "appended to" : "written to") + " file: " + filePath;
        } catch (java.io.IOException e) {
            throw new R2CommandException("Error writing to file: " + e.getMessage());
        } catch (r4ghidra.repl.filesystem.R2FileSystemException e) {
            throw new R2CommandException(e.getMessage());
        }
    }
    
    /**
     * Get the current context
     */
    /**
     * Execute a command across multiple addresses using @@ syntax
     * 
     * @param cmd The command to execute with multi-address info
     * @return The combined result of executing the command at all addresses
     * @throws R2CommandException If the command cannot be executed
     */
    private String executeMultiAddressCommand(R2Command cmd) throws R2CommandException {
        String addressInfo = cmd.getMultiAddressInfo();
        List<Address> addresses = new ArrayList<>();
        
        // Get the addresses based on the @@ syntax
        if (addressInfo.startsWith("=")) {
            // @@= - Space-separated addresses
            addresses = parseSpaceSeparatedAddresses(addressInfo.substring(1));
        } else if (addressInfo.startsWith("c:")) {
            // @@c: - Command output addresses
            addresses = parseCommandOutputAddresses(addressInfo.substring(2));
        } else {
            throw new R2CommandException("Unknown @@ syntax: " + addressInfo);
        }
        
        if (addresses.isEmpty()) {
            return "No valid addresses found for @@ command";
        }
        
        // Execute the command at each address and combine results
        StringBuilder result = new StringBuilder();
        Address originalSeek = context.getCurrentAddress();
        
        try {
            for (Address address : addresses) {
                // Set the temporary address
                context.setCurrentAddress(address);
                
                // Execute the command
                String cmdResult = executeCommandWithHandler(cmd);
                
                // Add a header with the address
                result.append("--- @ ").append(context.formatAddress(address)).append(" ---\n");
                result.append(cmdResult);
                if (!cmdResult.endsWith("\n")) {
                    result.append("\n");
                }
            }
        } finally {
            // Restore the original seek position
            context.setCurrentAddress(originalSeek);
        }
        
        return result.toString();
    }
    
    /**
     * Parse space-separated addresses for @@= syntax
     * 
     * @param addressStr The address string after @@=
     * @return A list of addresses
     */
    private List<Address> parseSpaceSeparatedAddresses(String addressStr) throws R2CommandException {
        List<Address> addresses = new ArrayList<>();
        String[] parts = addressStr.trim().split("\\s+");
        
        for (String part : parts) {
            if (part.trim().isEmpty()) {
                continue;
            }
            
            try {
                // Use R2NumUtil directly for complex expressions
                long addrValue = r4ghidra.repl.num.R2NumUtil.evaluateExpression(context, part.trim());
                Address address = context.getAPI().toAddr(addrValue);
                addresses.add(address);
            } catch (r4ghidra.repl.num.R2NumException e) {
                try {
                    // Fall back to direct conversion
                    Address address = context.parseAddress(part.trim());
                    addresses.add(address);
                } catch (Exception ex) {
                    // Skip invalid addresses
                }
            } catch (Exception e) {
                // Skip invalid addresses
            }
        }
        
        return addresses;
    }
    
    /**
     * Parse command output for addresses in @@c: syntax
     * 
     * @param command The command to execute
     * @return A list of addresses from the command output
     */
    private List<Address> parseCommandOutputAddresses(String command) throws R2CommandException {
        List<Address> addresses = new ArrayList<>();
        
        // Execute the command to get potential addresses
        String output = executeCommand(command);
        String[] lines = output.split("\\n");
        
        for (String line : lines) {
            // Split each line by whitespace and try to parse each token as an address
            String[] tokens = line.trim().split("\\s+");
            for (String token : tokens) {
                if (token.trim().isEmpty()) {
                    continue;
                }
                
                try {
                    // Use R2NumUtil directly for complex expressions
                    long addrValue = r4ghidra.repl.num.R2NumUtil.evaluateExpression(context, token.trim());
                    Address address = context.getAPI().toAddr(addrValue);
                    addresses.add(address);
                } catch (r4ghidra.repl.num.R2NumException e) {
                    try {
                        // Fall back to direct conversion
                        Address address = context.parseAddress(token.trim());
                        addresses.add(address);
                    } catch (Exception ex) {
                        // Skip tokens that are not valid addresses
                    }
                } catch (Exception e) {
                    // Skip tokens that are not valid addresses
                }
            }
        }
        
        return addresses;
    }
    
    /**
     * Parse a command with @@ syntax for multiple command execution
     * 
     * @param cmdStr The command string with @@ syntax
     * @return The parsed command with the addresses parsed
     * @throws R2CommandException If the command cannot be parsed
     */
    private R2Command parseMultiAddressCommand(String cmdStr) throws R2CommandException {
        // Split the command into the main part and the @@ part
        String[] parts = cmdStr.split("@@", 2);
        if (parts.length != 2) {
            throw new R2CommandException("Invalid @@ command syntax");
        }
        
        String mainCommand = parts[0].trim();
        String addressPart = parts[1].trim();
        
        // Create a basic command object without temporary address
        // We'll add the multiple addresses later in executeCommand
        if (mainCommand.isEmpty()) {
            throw new R2CommandException("Empty command");
        }
        
        String prefix = String.valueOf(mainCommand.charAt(0));
        String subcommand = mainCommand.length() > 1 ? mainCommand.substring(1) : "";
        
        List<String> args = new ArrayList<>();
        
        // Parse arguments based on spaces, but respect quoted strings
        if (subcommand.contains(" ")) {
            int spacePos = subcommand.indexOf(" ");
            String argsPart = subcommand.substring(spacePos).trim();
            subcommand = subcommand.substring(0, spacePos);
            
            // Parse arguments with proper handling of quoted strings
            Pattern pattern = Pattern.compile("[^\\s\"']+|\"([^\"]*)\"|\'([^']*)'\'");
            Matcher matcher = pattern.matcher(argsPart);
            
            while (matcher.find()) {
                if (matcher.group(1) != null) {
                    // Add double-quoted string without quotes
                    args.add(matcher.group(1));
                } else if (matcher.group(2) != null) {
                    // Add single-quoted string without quotes
                    args.add(matcher.group(2));
                } else {
                    // Add unquoted word
                    args.add(matcher.group());
                }
            }
        }
        
        // Create the command with the parsed components and null address
        // We'll use the special field in R2Command to indicate it's a @@ command
        // with specific address syntax
        R2Command cmd = new R2Command(prefix, subcommand, args, null);
        
        // Store the address part in the command arguments for later processing
        // We'll use the command arguments to store the @@ syntax information
        cmd.setMultiAddressInfo(addressPart);
        
        return cmd;
    }
    
    public R2Context getContext() {
        return context;
    }
    
    /**
     * Add a command to the history
     * 
     * @param cmd The command to add
     */
    public void addToHistory(String cmd) {
        if (cmd != null && !cmd.trim().isEmpty()) {
            // Don't add duplicate consecutive commands
            if (commandHistory.isEmpty() || !cmd.equals(commandHistory.get(commandHistory.size() - 1))) {
                commandHistory.add(cmd);
            }
        }
    }
    
    /**
     * Get the command history
     * 
     * @return The list of commands in history
     */
    public List<String> getCommandHistory() {
        return commandHistory;
    }
    
    /**
     * Test the comment handling implementation
     * This method is used for internal testing and returns a string with test results
     * 
     * @return A string containing the test results
     */
    public String testCommentHandling() {
        StringBuilder results = new StringBuilder();
        results.append("R2 Comment Handling Tests\n");
        results.append("=======================\n");
        
        // Test 1: Basic comment handling
        String test1 = "?e hello # world";
        String processed1 = processComments(test1);
        results.append("Test 1: Basic comment handling\n");
        results.append("  Input: ").append(test1).append("\n");
        results.append("  Output: ").append(processed1).append("\n");
        results.append("  Expected: ?e hello\n");
        results.append("  Result: ").append(processed1.equals("?e hello") ? "PASS" : "FAIL").append("\n\n");
        
        // Test 2: Quoted comment handling
        String test2 = "'?e hello # world";
        String processed2 = processComments(test2);
        results.append("Test 2: Quoted comment handling\n");
        results.append("  Input: ").append(test2).append("\n");
        results.append("  Output: ").append(processed2).append("\n");
        results.append("  Expected: '?e hello # world\n");
        results.append("  Result: ").append(processed2.equals("'?e hello # world") ? "PASS" : "FAIL").append("\n\n");
        
        // Test 3: Comment-only command
        String test3 = "# this is just a comment";
        String processed3 = processComments(test3);
        results.append("Test 3: Comment-only command\n");
        results.append("  Input: ").append(test3).append("\n");
        results.append("  Output: ").append(processed3).append("\n");
        results.append("  Expected: \n");
        results.append("  Result: ").append(processed3.isEmpty() ? "PASS" : "FAIL").append("\n\n");
        
        // Test 4: Command with quoted string containing #
        String test4 = "?e \"hello # not a comment\"";
        String processed4 = processComments(test4);
        results.append("Test 4: Command with quoted string containing #\n");
        results.append("  Input: ").append(test4).append("\n");
        results.append("  Output: ").append(processed4).append("\n");
        results.append("  Expected: ?e \"hello # not a comment\"\n");
        results.append("  Result: ").append(processed4.equals("?e \"hello # not a comment\"") ? "PASS" : "FAIL").append("\n\n");
        
        // Test 5: Multiple commands with comments
        String test5 = "?e hello; ?e world # comment";
        String[] commands = splitBySemicolon(test5);
        results.append("Test 5: Multiple commands with comments\n");
        results.append("  Input: ").append(test5).append("\n");
        results.append("  Split result: [" + commands[0] + ", " + commands[1] + "]\n");
        String processed5a = processComments(commands[0]);
        String processed5b = processComments(commands[1]);
        results.append("  Processed first command: ").append(processed5a).append("\n");
        results.append("  Processed second command: ").append(processed5b).append("\n");
        results.append("  Expected first: ?e hello\n");
        results.append("  Expected second: ?e world\n");
        results.append("  Result: ").append(processed5a.equals("?e hello") && processed5b.equals(" ?e world") ? "PASS" : "FAIL").append("\n\n");
        
        return results.toString();
    }
    
    /**
     * Display the command history as a formatted string
     * 
     * @param json Whether to return the history as JSON
     * @return Formatted history as a string
     */
    public String displayCommandHistory(boolean json) {
        if (commandHistory.isEmpty()) {
            return "No command history available.\n";
        }
        
        // Check if JSON output is requested
        if (json) {
            org.json.JSONArray jsonArray = new org.json.JSONArray();
            for (int i = 0; i < commandHistory.size(); i++) {
                jsonArray.put(commandHistory.get(i));
            }
            return jsonArray.toString() + "\n";
        }
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < commandHistory.size(); i++) {
            sb.append(i + 1).append("  ").append(commandHistory.get(i)).append("\n");
        }
        return sb.toString();
    }
}