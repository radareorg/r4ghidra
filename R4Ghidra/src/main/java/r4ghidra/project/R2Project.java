package r4ghidra.project;

import java.util.ArrayList;
import java.util.List;

/** Native representation of radare2's binary RPRJ project format. Addresses are unsigned. */
public final class R2Project {
  public String name = "";
  public String user = "";

  /** Microseconds since the Unix epoch, as in r_time_now(). */
  public long time;

  public final List<Mapping> maps = new ArrayList<>();
  public final List<Mapping> modules = new ArrayList<>();
  public final List<Flag> flags = new ArrayList<>();
  public final List<Comment> comments = new ArrayList<>();
  public final List<Function> functions = new ArrayList<>();
  public final List<Xref> xrefs = new ArrayList<>();
  public final List<String> warnings = new ArrayList<>();

  /** Bounds are inclusive. The final field is permissions for maps, checksum for modules. */
  public record Mapping(
      String name, String file, long pmin, long pmax, long vmin, long vmax, int attributes) {}

  /** Module -1 denotes an absolute address; (-1, -1L) denotes a missing jump/fail target. */
  public record Location(int module, long delta) {
    public static Location absolute(long address) {
      return new Location(-1, address);
    }
  }

  /** Extras are space, realname, rawname, type, color, comment, alias (null means absent). */
  public record Flag(
      String name, Location location, long size, List<String> extras, boolean demangled) {
    public Flag(String name, Location location, long size) {
      this(name, location, size, java.util.Arrays.asList(new String[7]), false);
    }
  }

  public record Comment(String text, Location location, long size) {}

  public record Xref(Location from, Location to, int type) {}

  public record FunctionAttributes(
      String callingConvention, int type, int bits, int flags, long stack) {}

  public record Block(Location location, long size, Location jump, Location fail) {}

  public record Variable(String name, String type, int delta, int kind, boolean argument) {}

  public record Function(
      String name,
      Location location,
      FunctionAttributes attributes,
      List<Block> blocks,
      List<Variable> variables) {}

  public long resolve(Location location) {
    if (location.module() == -1) {
      return location.delta();
    }
    Mapping module = modules.get(location.module());
    return module.vmin() + location.delta();
  }

  public Location locate(long address) {
    for (int i = 0; i < modules.size(); i++) {
      Mapping module = modules.get(i);
      if (Long.compareUnsigned(address, module.vmin()) >= 0
          && Long.compareUnsigned(address, module.vmax()) <= 0) {
        return new Location(i, address - module.vmin());
      }
    }
    return Location.absolute(address);
  }
}
