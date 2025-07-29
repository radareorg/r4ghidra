package r4ghidra.repl;

import ghidra.program.model.address.Address;
import java.util.Collections;
import java.util.List;

/**
 * Represents a parsed radare2 command
 *
 * <p>This class encapsulates all the components of a parsed r2 command, including: - Command prefix
 * (first character) - Subcommand (remaining characters before any space) - Arguments (parsed with
 * proper handling of quoted strings) - Temporary address for @ syntax
 */
public class R2Command {
  private String prefix;
  private String subcommand;
  private List<String> arguments;
  private Address temporaryAddress;
  private String multiAddressInfo; // For @@ command syntax

  /**
   * Create a new R2Command
   *
   * @param prefix The command prefix (first character)
   * @param subcommand The subcommand (remaining characters)
   * @param arguments The parsed arguments
   * @param temporaryAddress The temporary address from @ syntax, or null if not present
   */
  public R2Command(
      String prefix, String subcommand, List<String> arguments, Address temporaryAddress) {
    this.prefix = prefix;
    this.subcommand = subcommand;
    this.arguments = arguments != null ? arguments : Collections.emptyList();
    this.temporaryAddress = temporaryAddress;
    this.multiAddressInfo = null;
  }

  /** 
   * Get the command prefix (first character of the command)
   * 
   * @return The command prefix as a string
   */
  public String getPrefix() {
    return prefix;
  }

  /** 
   * Get the subcommand (everything after the prefix and before any space)
   * 
   * @return The subcommand as a string
   */
  public String getSubcommand() {
    return subcommand;
  }

  /**
   * Get the command suffix, which is a special character at the end of the subcommand that
   * determines the output format. Returns null if no special suffix is present.
   *
   * <p>Common suffixes in radare2: - 'j': JSON output - '*': radare2 commands output - ',':
   * CSV/table output - '?': help/documentation - 'q': quiet output - '?*': recursive help
   * documentation
   *
   * @return The command suffix character, or null if none
   */
  public Character getCommandSuffix() {
    // If no subcommand, return default suffix '\0'
    if (subcommand == null || subcommand.isEmpty()) {
      return Character.valueOf((char) 0);
    }
    // Special case for "?*" suffix (recursive help)
    if (subcommand.endsWith("?*")) {
      return Character.valueOf('*'); // Return '*' for recursive help
    }
    // Last character of subcommand
    char lastChar = subcommand.charAt(subcommand.length() - 1);
    // Check if the last character is one of the special suffixes
    if (lastChar == 'j'
        || lastChar == '*'
        || lastChar == ','
        || lastChar == '?'
        || lastChar == 'q') {
      return Character.valueOf(lastChar);
    }
    // Default: no suffix, return '\0'
    return Character.valueOf((char) 0);
  }

  /**
   * Get the subcommand without any special suffix character
   *
   * @return The subcommand with any suffix character removed
   */
  public String getSubcommandWithoutSuffix() {
    // Special case for "?*" suffix
    if (subcommand != null && subcommand.endsWith("?*")) {
      return subcommand.substring(0, subcommand.length() - 2);
    }

    Character suffix = getCommandSuffix();
    // If no suffix (zero char), return original subcommand
    if (suffix.charValue() == (char) 0) {
      return subcommand;
    }
    // Strip one character suffix
    return subcommand.substring(0, subcommand.length() - 1);
  }

  /**
   * Check if the command has a specific suffix
   *
   * @param suffix The suffix character to check for
   * @return true if the command has this suffix, false otherwise
   */
  public boolean hasSuffix(char suffix) {
    Character commandSuffix = getCommandSuffix();
    return commandSuffix != null && commandSuffix == suffix;
  }

  /**
   * Check if the command has the recursive help suffix (?*)
   *
   * @return true if the command has the recursive help suffix, false otherwise
   */
  public boolean hasRecursiveHelpSuffix() {
    return subcommand != null && subcommand.endsWith("?*");
  }

  /** 
   * Get all arguments as a list
   * 
   * @return An unmodifiable list of command arguments
   */
  public List<String> getArguments() {
    return Collections.unmodifiableList(arguments);
  }

  /** 
   * Get a specific argument by index, or defaultValue if the index is out of range
   * 
   * @param index The index of the argument to retrieve
   * @param defaultValue The value to return if the index is out of range
   * @return The argument at the specified index or the default value
   */
  public String getArgument(int index, String defaultValue) {
    if (index >= 0 && index < arguments.size()) {
      return arguments.get(index);
    }
    return defaultValue;
  }

  /** 
   * Get the first argument, or defaultValue if there are no arguments
   * 
   * @param defaultValue The value to return if there are no arguments
   * @return The first argument or the default value
   */
  public String getFirstArgument(String defaultValue) {
    return getArgument(0, defaultValue);
  }

  /** 
   * Get the number of arguments
   * 
   * @return The number of arguments
   */
  public int getArgumentCount() {
    return arguments.size();
  }

  /** 
   * Check if this command has a temporary address specified via @ syntax
   * 
   * @return True if a temporary address is specified, false otherwise
   */
  public boolean hasTemporaryAddress() {
    return temporaryAddress != null;
  }

  /** 
   * Get the temporary address specified via @ syntax
   * 
   * @return The temporary address or null if not specified
   */
  public Address getTemporaryAddress() {
    return temporaryAddress;
  }

  /** 
   * Check if this command matches the given prefix
   * 
   * @param prefix The prefix to check against
   * @return True if the command has the specified prefix, false otherwise
   */
  public boolean hasPrefix(String prefix) {
    return this.prefix.equals(prefix);
  }

  /** 
   * Check if this command matches the given prefix and subcommand
   * 
   * @param prefix The prefix to check against
   * @param subcommand The subcommand to check against
   * @return True if both the prefix and subcommand match, false otherwise
   */
  public boolean matches(String prefix, String subcommand) {
    return this.prefix.equals(prefix) && this.subcommand.equals(subcommand);
  }

  /** 
   * Check if the subcommand starts with the given string
   * 
   * @param str The string to check against
   * @return True if the subcommand starts with the specified string, false otherwise
   */
  public boolean subcommandStartsWith(String str) {
    return subcommand.startsWith(str);
  }

  /** 
   * Check if this command uses the @@ syntax for multiple addresses
   * 
   * @return True if this command uses multiple address syntax, false otherwise
   */
  public boolean hasMultiAddressInfo() {
    return multiAddressInfo != null && !multiAddressInfo.isEmpty();
  }

  /** 
   * Get the multi-address information (part after @@) for this command
   * 
   * @return The multi-address information string or null if not specified
   */
  public String getMultiAddressInfo() {
    return multiAddressInfo;
  }

  /** 
   * Set the multi-address information for this command
   * 
   * @param info The multi-address information to set
   */
  public void setMultiAddressInfo(String info) {
    this.multiAddressInfo = info;
  }

  /** Create a string representation of this command */
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
