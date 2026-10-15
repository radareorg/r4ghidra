package r4ghidra.repl.sandbox;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Capability policy for REPL operations; grains name allowed resources, as in radare2. */
public final class R2Sandbox {
  public static final int NONE = 0;
  public static final int SOCKET = 1;
  public static final int DISK = 2;
  public static final int FILES = 4;
  public static final int EXEC = 8;
  public static final int ENVIRON = 16;
  public static final int NETWORK = 32;
  public static final int HIDDEN = 64;
  public static final int ALL = SOCKET | DISK | FILES | EXEC | ENVIRON | NETWORK | HIDDEN;

  private static final Map<String, Integer> GRAINS = new LinkedHashMap<>();

  static {
    GRAINS.put("socket", SOCKET);
    GRAINS.put("disk", DISK);
    GRAINS.put("files", FILES);
    GRAINS.put("exec", EXEC);
    GRAINS.put("environ", ENVIRON);
    GRAINS.put("network", NETWORK);
    GRAINS.put("hidden", HIDDEN);
  }

  private boolean enabled = true;
  private int grains = NONE;
  private boolean locked;

  public synchronized boolean isEnabled() {
    return enabled;
  }

  public synchronized int getGrains() {
    return grains;
  }

  public synchronized void setEnabled(boolean value) {
    if (locked && !value) {
      throw new IllegalArgumentException("Cannot disable a locked sandbox");
    }
    enabled = value;
  }

  public synchronized void setGrains(int value) {
    if ((value & ~ALL) != 0) {
      throw new IllegalArgumentException("Unknown sandbox grain bits");
    }
    if (locked && (value & grains) != value) {
      throw new IllegalArgumentException("Cannot increase locked sandbox permissions");
    }
    grains = value;
  }

  /** Freeze the current permissions as a ceiling for untrusted commands, such as HTTP requests. */
  public synchronized void lock() {
    enabled = true;
    locked = true;
  }

  public synchronized boolean isRestricted(int resources) {
    return enabled && (grains & resources) != resources;
  }

  /** Parse comma-separated permissions, with a leading ! starting from all permissions. */
  public static int parseGrains(String expression) {
    String expr = expression.trim().toLowerCase(Locale.ROOT);
    int result = expr.startsWith("!") ? ALL : NONE;
    for (String part : expr.split(",", -1)) {
      String name = part.trim();
      boolean remove = name.startsWith("!");
      if (remove) {
        name = name.substring(1).trim();
      }
      Integer grain =
          switch (name) {
            case "all" -> ALL;
            case "none" -> NONE;
            case "file" -> FILES;
            default -> GRAINS.get(name);
          };
      if (grain == null) {
        throw new IllegalArgumentException("Invalid sandbox grain: " + part.trim());
      }
      if (remove) {
        result &= ~grain;
      } else if (grain == NONE) {
        result = NONE;
      } else {
        result |= grain;
      }
    }
    return result;
  }

  public static String formatGrains(int grains) {
    if (grains == NONE) {
      return "none";
    }
    if (grains == ALL) {
      return "all";
    }
    StringBuilder result = new StringBuilder();
    GRAINS.forEach(
        (name, grain) -> {
          if ((grains & grain) != 0) {
            if (result.length() > 0) {
              result.append(',');
            }
            result.append(name);
          }
        });
    return result.toString();
  }

  public static String getHelp() {
    return "Usage: e cfg.sandbox.grain=permission[,permission...]\n"
        + " all / none     allow all / no resources\n"
        + " files          read files, list directories and inspect file existence\n"
        + " disk           write, append and delete files (also requires files)\n"
        + " exec           execute shell commands, external pipes and process exit\n"
        + " environ        read or modify environment variables\n"
        + " hidden         access dotfiles and hidden directories (also requires files)\n"
        + " socket/network reserved for socket operations / non-local network access\n"
        + " !name          remove a permission; leading ! starts from all\n"
        + " Example: e cfg.sandbox.grain=files,disk\n"
        + " JavaScript requires all permissions because it has unrestricted JVM access.\n";
  }
}
