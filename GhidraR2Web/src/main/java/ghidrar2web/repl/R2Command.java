package ghidrar2web.repl;

import java.util.Collections;
import java.util.List;

import ghidra.program.model.address.Address;

/**
 * Represents a parsed radare2 command
 * 
 * This class encapsulates all the components of a parsed r2 command, including:
 * - Command prefix (first character)
 * - Subcommand (remaining characters before any space)
 * - Arguments (parsed with proper handling of quoted strings)
 * - Temporary address for @ syntax
 */
public class R2Command {
    private String prefix;
    private String subcommand;
    private List<String> arguments;
    private Address temporaryAddress;

    /**
     * Create a new R2Command
     * 
     * @param prefix The command prefix (first character)
     * @param subcommand The subcommand (remaining characters)
     * @param arguments The parsed arguments
     * @param temporaryAddress The temporary address from @ syntax, or null if not present
     */
    public R2Command(String prefix, String subcommand, List<String> arguments, Address temporaryAddress) {
        this.prefix = prefix;
        this.subcommand = subcommand;
        this.arguments = arguments != null ? arguments : Collections.emptyList();
        this.temporaryAddress = temporaryAddress;
    }

    /**
     * Get the command prefix (first character of the command)
     */
    public String getPrefix() {
        return prefix;
    }

    /**
     * Get the subcommand (everything after the prefix and before any space)
     */
    public String getSubcommand() {
        return subcommand;
    }

    /**
     * Get all arguments as a list
     */
    public List<String> getArguments() {
        return Collections.unmodifiableList(arguments);
    }
    
    /**
     * Get a specific argument by index, or defaultValue if the index is out of range
     */
    public String getArgument(int index, String defaultValue) {
        if (index >= 0 && index < arguments.size()) {
            return arguments.get(index);
        }
        return defaultValue;
    }
    
    /**
     * Get the first argument, or defaultValue if there are no arguments
     */
    public String getFirstArgument(String defaultValue) {
        return getArgument(0, defaultValue);
    }

    /**
     * Get the number of arguments
     */
    public int getArgumentCount() {
        return arguments.size();
    }

    /**
     * Check if this command has a temporary address specified via @ syntax
     */
    public boolean hasTemporaryAddress() {
        return temporaryAddress != null;
    }

    /**
     * Get the temporary address specified via @ syntax
     */
    public Address getTemporaryAddress() {
        return temporaryAddress;
    }

    /**
     * Check if this command matches the given prefix
     */
    public boolean hasPrefix(String prefix) {
        return this.prefix.equals(prefix);
    }

    /**
     * Check if this command matches the given prefix and subcommand
     */
    public boolean matches(String prefix, String subcommand) {
        return this.prefix.equals(prefix) && this.subcommand.equals(subcommand);
    }

    /**
     * Check if the subcommand starts with the given string
     */
    public boolean subcommandStartsWith(String str) {
        return subcommand.startsWith(str);
    }
    
    /**
     * Create a string representation of this command
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix).append(subcommand);
        
        for (String arg : arguments) {
            sb.append(" ");
            // Add quotes if the argument contains spaces
            if (arg.contains(" ")) {
                sb.append("\"").append(arg).append("\"");
            } else {
                sb.append(arg);
            }
        }
        
        if (temporaryAddress != null) {
            sb.append(" @").append(temporaryAddress.toString());
        }
        
        return sb.toString();
    }
}