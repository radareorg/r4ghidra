package ghidrar2web.repl.handlers;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;

import ghidrar2web.repl.R2Command;
import ghidrar2web.repl.R2CommandException;
import ghidrar2web.repl.R2CommandHandler;
import ghidrar2web.repl.R2Context;

/**
 * Handler for the '!' (shell) command - Execute external shell commands
 */
public class R2ShellCommandHandler implements R2CommandHandler {

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if this is a '!' command
        if (!command.hasPrefix("!")) {
            throw new R2CommandException("Not a shell command");
        }
        
        // Get the raw command string and strip the '!' prefix
        String cmdLine = command.getPrefix() + command.getSubcommand();
        
        // Handle different shell command types
        if (cmdLine.startsWith("!!")) {
            // !! - Capture output and return it
            return executeShellWithCapture(cmdLine.substring(2).trim());
        } else {
            // ! - Execute and return exit code
            return executeShell(cmdLine.substring(1).trim());
        }
    }
    
    /**
     * Execute a shell command with output capture
     * 
     * @param shellCmd The shell command to execute
     * @return The captured output of the command
     */
    private String executeShellWithCapture(String shellCmd) throws R2CommandException {
        if (shellCmd.isEmpty()) {
            return "";
        }
        
        try {
            // Create process builder with shell command
            ProcessBuilder processBuilder = createProcessBuilder(shellCmd);
            
            // Start the process
            Process process = processBuilder.start();
            
            // Capture output
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            
            // Capture error output
            StringBuilder errorOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }
            }
            
            // Wait for process to complete (with timeout)
            boolean completed = process.waitFor(60, TimeUnit.SECONDS);
            if (!completed) {
                process.destroyForcibly();
                throw new R2CommandException("Command execution timed out after 60 seconds");
            }
            
            // Check exit code
            int exitCode = process.exitValue();
            
            // If error output exists and exit code is not 0, add it to the output
            if (exitCode != 0 && errorOutput.length() > 0) {
                output.append("\nError output:\n").append(errorOutput);
            }
            
            return output.toString();
            
        } catch (IOException e) {
            throw new R2CommandException("IO error executing command: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new R2CommandException("Command execution interrupted");
        }
    }
    
    /**
     * Execute a shell command without capturing output
     * This is meant for interactive commands that send output directly to the terminal
     * 
     * @param shellCmd The shell command to execute
     * @return A simple status message with the exit code
     */
    private String executeShell(String shellCmd) throws R2CommandException {
        if (shellCmd.isEmpty()) {
            return "";
        }
        
        try {
            // Create process builder with shell command
            ProcessBuilder processBuilder = createProcessBuilder(shellCmd);
            
            // Inherit IO streams to allow interactive use
            processBuilder.inheritIO();
            
            // Start the process
            Process process = processBuilder.start();
            
            // Wait for process to complete
            int exitCode = process.waitFor();
            
            // Return simple status message
            return "Process exited with code: " + exitCode + "\n";
            
        } catch (IOException e) {
            throw new R2CommandException("IO error executing command: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new R2CommandException("Command execution interrupted");
        }
    }
    
    /**
     * Create a process builder for the given shell command
     */
    private ProcessBuilder createProcessBuilder(String shellCmd) {
        List<String> command = new ArrayList<>();
        
        // Determine shell based on OS
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            // Windows
            command.add("cmd.exe");
            command.add("/c");
            command.add(shellCmd);
        } else {
            // Unix-like
            command.add("/bin/sh");
            command.add("-c");
            command.add(shellCmd);
        }
        
        // Create and configure process builder
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        
        // Set working directory to current directory
        processBuilder.directory(new File(System.getProperty("user.dir")));
        
        return processBuilder;
    }

    @Override
    public String getHelp() {
        StringBuilder help = new StringBuilder();
        help.append("Usage: ![!]cmd\n");
        help.append(" !cmd           run shell command and redirect output to terminal\n");
        help.append(" !!cmd          run shell command and capture output\n");
        help.append(" .!cmd          run shell command and execute output as r2 commands\n");
        help.append("\nExamples:\n");
        help.append(" !ls            list files in current directory (interactive)\n");
        help.append(" !!ls           capture and return the output of ls\n");
        help.append(" !!ls -la | grep \"\\.java$\"   run complex shell commands and capture output\n");
        help.append(" .!rabin2 -ri $FILE     run external tool and execute its output as r2 script\n");
        return help.toString();
    }
}