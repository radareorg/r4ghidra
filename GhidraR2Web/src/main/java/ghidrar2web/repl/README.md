# R2REPL - Extensible Radare2 Command Implementation for Ghidra

This implementation provides a flexible and extensible framework for handling radare2 commands in the Ghidra R2Web plugin. It replaces the previous flat command handling system with a more robust architecture that supports complex command syntax and features.

## Architecture Overview

The R2REPL architecture consists of:

1. **R2REPLImpl** - Main REPL implementation that manages command parsing and execution
2. **R2Command** - Command representation with parsed prefix, subcommand, arguments, and temporary address
3. **R2CommandHandler** - Interface for all command handlers
4. **R2Context** - Context object for command execution, manages state like current seek, blocksize, etc.
5. **Command Handlers** - Individual implementations of R2CommandHandler for each command (located in the handlers package)

## Features

- **Hierarchical command structure** - Easily add new commands and subcommands
- **Advanced parsing** - Properly handles command syntax, quoted strings, etc.
- **Special syntax support**:
  - `@addr` for temporary seek operations
  - `` `cmd` `` for command output substitution
  - `'cmd` for literal command interpretation (no special character processing)
  - `.cmd` for script execution (execute command and interpret its output as r2 commands)
  - `!cmd` for executing shell commands
  - `~pattern` for filtering output (grep, JSON pretty print, line counting)
  - `|cmd` for piping output to shell commands
  - Output formats with suffixes: `j` (JSON), `*` (r2 commands), `,` (CSV), `?` (help), `q` (quiet)
- **Error handling** - Structured error reporting and exception system
- **Help system** - Built-in help for all commands
- **Context management** - Clean separation of state and command execution
- **Extensibility** - Easy to add new commands by implementing R2CommandHandler

## Integrating with GhidraR2Web

To integrate this new REPL system with the existing GhidraR2Web plugin:

1. Replace the current `GhidraR2WebCmdHandler` with the new `GhidraR2WebREPLHandler` in the server setup:

```java
// In GhidraR2WebServer or wherever the HTTP server is initialized
HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
// Replace this:
// server.createContext("/r2", new GhidraR2WebCmdHandler());
// With this:
server.createContext("/r2", new ghidrar2web.repl.GhidraR2WebREPLHandler());
```

2. Implement additional command handlers for all the required radare2 commands:
   - Each command should have its own class implementing R2CommandHandler in the handlers package
   - Register each handler in GhidraR2WebREPLHandler.registerCommandHandlers()

## Adding New Commands

To add a new command handler:

1. Create a new class in the `ghidrar2web.repl.handlers` package that implements R2CommandHandler
2. Implement the `execute` and `getHelp` methods
3. Register the handler in GhidraR2WebREPLHandler:

```java
private void registerCommandHandlers() {
    // Existing handlers...
    
    // Add your new command handler
    R2YourCommandHandler yourHandler = new R2YourCommandHandler();
    commandRegistry.put("y", yourHandler); // The command prefix
    repl.registerCommand("y", yourHandler);
}
```

## Command Syntax Features

### Output Format Suffixes

Commands can have special suffixes that determine their output format:

- `j` - Output as JSON (e.g., `pdj`, `?j`, `sj`)
- `*` - Output as radare2 commands (e.g., `pdd*`, `af*`)
- `,` - Output as CSV/table format
- `q` - Quiet output (minimal output, e.g., `?q`, `pddq`)
- `?` - Show help for the command

To handle these in your command implementation:

```java
if (command.hasSuffix('j')) {
    // Generate JSON output
} else if (command.hasSuffix('*')) {
    // Generate r2 commands
}
```

### Output Filtering (~)

Commands can be filtered using the `~` operator:

```
pdd~main     # Filter decompilation output for lines containing "main"
afl~?        # Count the number of functions
pdj~{}       # Pretty print JSON output from pdj
```

Types of filters:
- `~pattern` - Grep filter, only shows lines matching the pattern
- `~{}` - Pretty-prints JSON output
- `~?` - Counts lines in output (like wc -l)

Pattern modifiers:
- `^pattern` - Match at start of line
- `pattern$` - Match at end of line
- `pat*tern` - Glob-style wildcard matching

### Shell Command Execution (!)

Commands that start with `!` execute shell commands:

```
!ls -la
```

There are two variants:

- `!cmd` - Execute command and redirect output to terminal (interactive)
- `!!cmd` - Execute command and capture output to return

Examples:
```
!ls            # List files in current directory (interactive)
!!ls -la       # Capture and return the output of ls
!!grep -r "main" .  # Search for "main" in all files
```

### Dot Commands (Script Execution)

Commands that start with a dot (`.`) are script execution commands:

```
.pdd*
```

This will:
1. Execute the command after the dot (`pdd*`)
2. Take the output from that command
3. Execute each line of the output as a separate radare2 command
4. Return the combined results

This is useful for:
- Running r2 commands from external scripts or files
- Reusing the output of commands that produce r2 script output (with the `*` suffix)
- Executing a series of commands stored in a file or another command's output

### Quoted Commands

Commands that start with a single quote (`'`) are treated specially:

```
'px 10 @ 0x100
```

When a command starts with a single quote:
- Special characters like backticks, pipes, or @ are treated as literal text
- No command substitution or temporary seek processing is performed
- The command is parsed and executed directly

This is useful for:
- Protection against command injection
- Faster execution with large scripts
- Situations where special characters need to be interpreted literally

### Temporary Address (@)

Normal (unquoted) commands support temporary seek with the `@` syntax:

```
px @ 0x1000
```

This will:
1. Temporarily set the current address to 0x1000
2. Execute the command
3. Restore the original address

### Command Substitution (backticks)

Normal (unquoted) commands support command substitution with backticks:

```
px `s`
```

This will:
1. Execute the inner command (s) to get the current address
2. Substitute the result into the outer command
3. Execute the resulting command

### Pipe Commands (|)

Commands can be piped to shell commands using the `|` operator:

```
pd | grep call
```

This will:
1. Execute the left command (pd) to get its output
2. Pipe that output as input to the right shell command (grep call)
3. Return the output of the shell command

Examples:
```
pd | grep -A2 mov   # Show lines containing 'mov' and 2 lines after
afl | sort -n       # List functions and sort numerically
pd | head -n 20     # Show only first 20 lines of decompilation
```

This feature works just like POSIX shell pipes and is an alternative to using the built-in grep filter (`~`).

## Example Command Handler

Here's an example of how to implement a command handler:

```java
package ghidrar2web.repl.handlers;

import ghidrar2web.repl.R2Command;
import ghidrar2web.repl.R2CommandException;
import ghidrar2web.repl.R2CommandHandler;
import ghidrar2web.repl.R2Context;
import org.json.JSONObject;

public class R2ExampleCommandHandler implements R2CommandHandler {
    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if this is our command
        if (!command.hasPrefix("x")) {
            throw new R2CommandException("Not an example command");
        }
        
        // Get base subcommand without suffix
        String subcommand = command.getSubcommandWithoutSuffix();
        
        // Handle basic command with no subcommand
        if (subcommand.isEmpty()) {
            // Format output based on suffix
            if (command.hasSuffix('j')) {
                JSONObject json = new JSONObject();
                json.put("result", "Example command executed!");
                return json.toString() + "\n";
            } else if (command.hasSuffix('q')) {
                return "executed";
            } else {
                return "Example command executed!\n";
            }
        }
        
        // Handle subcommands
        switch (subcommand) {
            case "1":
                return "Example subcommand 1\n";
            case "2":
                return "Example subcommand 2\n";
            default:
                throw new R2CommandException("Unknown subcommand: " + subcommand);
        }
    }
    
    @Override
    public String getHelp() {
        return "Usage: x[12][jq]\n" +
               " x     basic example command\n" +
               " x1    example subcommand 1\n" +
               " x2    example subcommand 2\n" +
               " xj    output as JSON\n" +
               " xq    quiet output\n";
    }
}
```