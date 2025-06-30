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

## Example Command Handler

Here's an example of how to implement a command handler:

```java
package ghidrar2web.repl.handlers;

import ghidrar2web.repl.R2Command;
import ghidrar2web.repl.R2CommandException;
import ghidrar2web.repl.R2CommandHandler;
import ghidrar2web.repl.R2Context;

public class R2ExampleCommandHandler implements R2CommandHandler {
    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if this is our command
        if (!command.hasPrefix("x")) {
            throw new R2CommandException("Not an example command");
        }
        
        // Get subcommand
        String subcommand = command.getSubcommand();
        
        // Handle basic command with no subcommand
        if (subcommand.isEmpty()) {
            return "Example command executed!\n";
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
        return "Usage: x[12]\n" +
               " x     basic example command\n" +
               " x1    example subcommand 1\n" +
               " x2    example subcommand 2\n";
    }
}
```