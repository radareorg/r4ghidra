# R2REPL - Extensible Radare2 Command Implementation for Ghidra

This implementation provides a flexible and extensible framework for handling radare2 commands in the Ghidra R2Web plugin. It replaces the previous flat command handling system with a more robust architecture that supports complex command syntax and features.

## Architecture Overview

The R2REPL architecture consists of:

1. **R2REPLImpl** - Main REPL implementation that manages command parsing and execution
2. **R2Command** - Command representation with parsed prefix, subcommand, arguments, and temporary address
3. **R2CommandHandler** - Interface for all command handlers
4. **R2Context** - Context object for command execution, manages state like current seek, blocksize, etc.
5. **Command Handlers** - Individual implementations of R2CommandHandler for each command (located in the handlers package)
6. **R2Num** - Advanced expression evaluator that provides radare2-compatible number parsing and calculations

## Features

- **Hierarchical command structure** - Easily add new commands and subcommands
- **Advanced parsing** - Properly handles command syntax, quoted strings, etc.
- **Special syntax support**:
  - `@addr` for temporary seek operations
  - `@@` for multiple command execution across different addresses
  - `` `cmd` `` for command output substitution
  - `'cmd` for literal command interpretation (no special character processing)
  - `.cmd` for script execution (execute command and interpret its output as r2 commands)
  - `!cmd` for executing shell commands
  - `~pattern` for filtering output (grep, JSON pretty print, line counting)
  - `|cmd` for piping output to shell commands
  - `>file` and `>>file` for redirecting output to files
  - `%var` for environment variable management
  - Output formats with suffixes: `j` (JSON), `*` (r2 commands), `,` (CSV), `?` (help), `q` (quiet)
- **Error handling** - Structured error reporting and exception system
- **Help system** - Built-in help for all commands
- **Context management** - Clean separation of state and command execution
- **Extensibility** - Easy to add new commands by implementing R2CommandHandler
- **Expression evaluation** - Powerful R2Num expression evaluator supporting different number bases, symbols, memory access, and math operations

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

Commands that start with a dot (`.`) are script execution commands. There are two forms:

#### 1. Command Output Execution
```
.pdd*
```

This will:
1. Execute the command after the dot (`pdd*`)
2. Take the output from that command
3. Execute each line of the output as a separate radare2 command
4. Return the combined results

#### 2. Script File Execution
```
. script.r2
```

Notice the space after the dot. This will:
1. Read the contents of the specified file (`script.r2`)
2. Execute each line of the file as a separate radare2 command
3. Return the combined results

This works exactly like the POSIX shell dot command (`. script.sh`), but for r2 commands.

#### 3. Shell Command Script Execution
```
.!command args
```

This will:
1. Execute the shell command and capture its output
2. Execute each line of the output as a separate radare2 command
3. Return the combined results

This is useful for running external tools that generate r2 commands.

Both forms are useful for:
- Running r2 commands from external scripts or files
- Reusing the output of commands that produce r2 script output (with the `*` suffix)
- Executing a series of commands stored in a file or another command's output

Examples:
```
. analysis.r2                     # Run commands from a script file
.pdd* > script.r2 && . script.r2   # Generate and then execute a script
.!rabin2 -ri $FILE                # Execute rabin2 and run its output as r2 commands
.!cat script.r2                   # Run script from a file using shell redirection
```

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

### Multiple Address Command Execution (@@)

The `@@` operator executes a command multiple times at different addresses:

#### 1. Space-Separated Addresses (@@=)
```
p8 4 @@= 0x1000 0x2000 0x3000
```

This will:
1. Execute the command `p8 4` at address 0x1000
2. Execute the command `p8 4` at address 0x2000
3. Execute the command `p8 4` at address 0x3000
4. Return the combined results with headers indicating each address

#### 2. Command Output Addresses (@@c:)
```
p8 4 @@c:`afl~[0]`
```

This will:
1. Execute the command inside the backticks (`afl~[0]`)
2. Parse the output as a list of addresses (from column 0 of the `afl` command)
3. Execute the command `p8 4` at each address found
4. Return the combined results

Examples:
```
p8 4 @@= 0x1000 0x2000 0x3000   # Show 4 bytes at each of the specified addresses
p8 4 @@c:`afl~[0]`              # Show 4 bytes at every function address
pd 10 @@c:`afl~main[0]`         # Disassemble 10 instructions at every function with 'main' in the name
```

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

### Output Redirection (> and >>)

Command output can be redirected to files using the `>` and `>>` operators:

```
pd > decompiled.txt      # Write output to file (create or overwrite)
pd >> decompiled.txt     # Append output to file
```

This will:
1. Execute the left command (pd) to get its output
2. Write that output to the specified file
3. Return a message indicating success or failure

Examples:
```
pdd* > script.r2        # Save decompiled code as r2 commands to a file
afl > functions.txt     # Save list of functions to a file
pddj > func.json       # Save JSON output to a file
pdj | python -m json.tool > formatted.json  # Combine pipe and redirection
```

The redirection operators work exactly like their POSIX shell counterparts:
- `>` creates a new file or overwrites an existing file
- `>>` creates a new file or appends to an existing file

### Environment Variables (%)

The `%` command allows you to manage environment variables:

```
%              # List all environment variables
%VAR           # Get the value of environment variable VAR
%VAR=value     # Set environment variable VAR to value
%*             # Show environment variables as r2 commands
%j             # Show environment variables in JSON format
```

Examples:
```
%              # List all environment variables
%PATH          # Show the PATH environment variable
%TMPDIR=/tmp   # Set the TMPDIR environment variable
%j             # List environment variables in JSON format
```

Note: Setting environment variables may not work on all JVM implementations due to security restrictions.

## R2Num Expression Evaluator

The `R2Num` class provides a powerful expression evaluation system compatible with radare2's RNum API. It allows for parsing and evaluating complex numeric expressions including:

- Different number bases (decimal, hexadecimal, binary, octal)
- Symbol resolution via callbacks
- Memory access with bracketed expressions
- Arithmetic and bitwise operations
- Parenthesized expressions

### Architecture

The R2Num implementation consists of:

1. **R2Num** - Core expression evaluator class
2. **R2NumCallback** - Interface for resolving symbol names
3. **R2MemoryReader** - Interface for reading memory values
4. **R2NumException** - Exception class for evaluation errors
5. **R2GhidraMemoryReader** - Ghidra implementation of the memory reader
6. **R2GhidraSymbolCallback** - Ghidra implementation of symbol resolver
7. **R2NumUtil** - Utility class for easier integration

### Features

- **Number bases**: Supports decimal, hexadecimal (`0x`), binary (`0b`), and octal (`0`) prefixes
- **Arithmetic operations**: `+`, `-`, `*`, `/`, `%`
- **Bitwise operations**: `&`, `|`, `^`, `~`, `>>`, `<<`
- **Symbol resolution**: Resolves symbol names like function names via callback
- **Memory access**: Can read memory with bracketed expressions like `[address:size]`
- **Expression composition**: Supports complex nested expressions with parentheses
- **Configurable**: Supports different endianness and word sizes

### Expression Syntax

- **Basic literals**: `123`, `0x7f`, `0b1010`, `01234`
- **Symbol names**: `main`, `entry0`, etc.
- **Arithmetic**: `1+2*3`, `(1+2)*3`
- **Memory access**: `[0x100]`, `[main+0x10:4]`
- **Combined**: `main+0x10`, `[main+0x10]+4`, etc.

### Using R2Num in Command Handlers

Here's how to use the R2Num system in your command handlers:

```java
import ghidrar2web.repl.num.R2NumUtil;
import ghidrar2web.repl.num.R2NumException;

public class YourCommandHandler implements R2CommandHandler {
    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Get an expression from a command argument
        String expr = command.getFirstArgument("");
        
        try {
            // Evaluate the expression
            long value = R2NumUtil.evaluateExpression(context, expr);
            
            // Use the value
            return "Result: 0x" + Long.toHexString(value) + "\n";
        } catch (R2NumException e) {
            throw new R2CommandException("Invalid expression: " + e.getMessage());
        }
    }
}
```

### Advanced Usage

For more complex scenarios, you can create and configure the R2Num instance directly:

```java
import ghidrar2web.repl.num.R2Num;
import ghidrar2web.repl.num.R2NumCallback;
import ghidrar2web.repl.num.R2MemoryReader;

// Create the evaluator
R2Num num = new R2Num(context);

// Set a custom symbol resolver
num.setCallback(new R2NumCallback() {
    @Override
    public Long resolveSymbol(String name) {
        // Your custom symbol resolution logic
        if (name.equals("custom_symbol")) {
            return 0x12345678L;
        }
        return null;
    }
});

// Set a custom memory reader
num.setMemoryReader(new R2MemoryReader() {
    @Override
    public long readMemory(long address, int size, boolean littleEndian) throws Exception {
        // Your custom memory reading logic
        return 0x42;
    }
});

// Configure the evaluator
num.setLittleEndian(true);
num.setDefaultSize(8); // 8-byte/64-bit reads

// Evaluate an expression
long result = num.getValue("custom_symbol + [0x1000:4]");
```

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