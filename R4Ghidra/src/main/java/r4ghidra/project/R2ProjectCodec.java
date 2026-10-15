package r4ghidra.project;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import r4ghidra.project.R2Project.*;

/**
 * Little-endian RPRJ reader/writer, based on libr/core/p/newprj in radare2. Supports versions 5 and
 * 6; writes version 6. No native library or r2 process is needed.
 */
public final class R2ProjectCodec {
  public static final int MAGIC = 0x4a525052;
  public static final int VERSION = 6;
  private static final int MAPS = 0,
      INFO = 1,
      FLAG = 2,
      CMNT = 3,
      MODS = 6,
      STRS = 7,
      XREF = 11,
      FUNC = 12;
  private static final String[] SECTION_NAMES = {
    "Maps",
    "Info",
    "Flags",
    "Comments",
    "Commands",
    "Blob",
    "Modules",
    "Strings",
    "Theme",
    "Hints",
    "Configuration",
    "Xrefs",
    "Functions",
    "Variable types",
    "Breakpoints",
    "Signals",
    "Types",
    "Type links",
    "Formats",
    "Globals"
  };

  private R2ProjectCodec() {}

  /** Parse and validate the complete supported data before callers modify a program. */
  public static R2Project read(byte[] data) throws IOException {
    try {
      ByteBuffer input = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
      require(input.remaining() >= 8 && input.getInt() == MAGIC, "Invalid RPRJ header");
      int version = input.getInt();
      require(version >= 5 && version <= VERSION, "Unsupported RPRJ version: " + version);
      Map<Integer, ByteBuffer> sections = new LinkedHashMap<>();
      while (input.hasRemaining()) {
        require(input.remaining() >= 8, "Truncated section header");
        long size = Integer.toUnsignedLong(input.getInt());
        int type = input.getInt();
        require(size >= 8 && size - 8 <= input.remaining(), "Invalid section size");
        require(!sections.containsKey(type), "Duplicate section: " + type);
        ByteBuffer section = input.slice().order(ByteOrder.LITTLE_ENDIAN);
        section.limit((int) size - 8);
        sections.put(type, section);
        input.position(input.position() + (int) size - 8);
      }
      ByteBuffer strings = sections.get(STRS);
      require(
          strings != null && strings.hasRemaining() && strings.get(strings.limit() - 1) == 0,
          "Missing or invalid string table");
      R2Project project = new R2Project();
      ByteBuffer modules = sections.get(MODS);
      if (modules != null) {
        readMappings(modules, strings, project.modules);
      }
      for (Map.Entry<Integer, ByteBuffer> entry : sections.entrySet()) {
        int type = entry.getKey();
        ByteBuffer b = entry.getValue();
        switch (type) {
          case STRS, MODS -> {
            continue;
          }
          case INFO -> {
            require(b.remaining() == 16, "Invalid info section");
            project.name = string(strings, b.getInt());
            project.user = string(strings, b.getInt());
            project.time = b.getLong();
          }
          case MAPS -> readMappings(b, strings, project.maps);
          case FLAG -> {
            int count = count(b, 21);
            for (int i = 0; i < count; i++) {
              String name = requiredString(strings, b.getInt());
              Location location = location(b, project);
              long size = Integer.toUnsignedLong(b.getInt());
              int bits = Byte.toUnsignedInt(b.get());
              List<String> extras = new ArrayList<>();
              for (int bit = 0; bit < 7; bit++) {
                extras.add((bits & (1 << bit)) == 0 ? null : string(strings, b.getInt()));
              }
              project.flags.add(new Flag(name, location, size, extras, (bits & 128) != 0));
            }
          }
          case CMNT -> {
            require(b.remaining() % 24 == 0, "Invalid comment section");
            while (b.hasRemaining()) {
              project.comments.add(
                  new Comment(
                      requiredString(strings, b.getInt()), location(b, project), b.getLong()));
            }
          }
          case XREF -> {
            int count = count(b, 28);
            for (int i = 0; i < count; i++) {
              project.xrefs.add(new Xref(location(b, project), location(b, project), b.getInt()));
            }
          }
          case FUNC -> readFunctions(b, strings, project);
          default -> {
            // Empty counted sections (e.g. EVAL) contain a single zero count.
            if (b.hasRemaining() && !(b.remaining() == 4 && b.getInt(b.position()) == 0)) {
              project.warnings.add(
                  "Skipped RPRJ section: "
                      + (type >= 0 && type < SECTION_NAMES.length
                          ? SECTION_NAMES[type]
                          : Integer.toUnsignedString(type)));
            }
            b.position(b.limit());
          }
        }
        require(!b.hasRemaining(), "Trailing data in section " + type);
      }
      return project;
    } catch (java.nio.BufferUnderflowException | IndexOutOfBoundsException e) {
      throw new IOException("Truncated RPRJ record", e);
    }
  }

  private static void readMappings(ByteBuffer b, ByteBuffer strings, List<Mapping> mappings)
      throws IOException {
    require(b.remaining() % 44 == 0, "Invalid mapping section");
    while (b.hasRemaining()) {
      Mapping mapping =
          new Mapping(
              string(strings, b.getInt()),
              string(strings, b.getInt()),
              b.getLong(),
              b.getLong(),
              b.getLong(),
              b.getLong(),
              b.getInt());
      require(
          Long.compareUnsigned(mapping.pmax(), mapping.pmin()) >= 0
              && Long.compareUnsigned(mapping.vmax(), mapping.vmin()) >= 0,
          "Invalid mapping bounds");
      mappings.add(mapping);
    }
  }

  private static void readFunctions(ByteBuffer b, ByteBuffer strings, R2Project project)
      throws IOException {
    int colors = count(b, 9);
    b.position(b.position() + colors * 9);
    int attrCount = count(b, 24);
    List<FunctionAttributes> attrs = new ArrayList<>();
    for (int i = 0; i < attrCount; i++) {
      attrs.add(
          new FunctionAttributes(
              string(strings, b.getInt()), b.getInt(), b.getInt(), b.getInt(), b.getLong()));
    }
    int count = count(b, 28);
    boolean colored = false;
    for (int i = 0; i < count; i++) {
      String name = requiredString(strings, b.getInt());
      Location location = location(b, project);
      int attr = b.getInt();
      require(attr == -1 || (attr >= 0 && attr < attrs.size()), "Invalid function attribute index");
      int blocks = count(b, 48);
      int variables = b.getInt();
      List<Block> body = new ArrayList<>();
      for (int j = 0; j < blocks; j++) {
        body.add(
            new Block(
                location(b, project), b.getLong(), location(b, project), location(b, project)));
        int color = b.getInt();
        require(color == -1 || (color >= 0 && color < colors), "Invalid block color index");
        colored |= color != -1;
      }
      require(variables >= 0 && variables <= b.remaining() / 16, "Invalid variable count");
      List<Variable> vars = new ArrayList<>();
      for (int j = 0; j < variables; j++) {
        vars.add(
            new Variable(
                string(strings, b.getInt()),
                string(strings, b.getInt()),
                b.getInt(),
                Byte.toUnsignedInt(b.get()),
                b.get() != 0));
        b.getShort(); // Reserved padding, not C struct alignment.
      }
      project.functions.add(
          new Function(name, location, attr == -1 ? null : attrs.get(attr), body, vars));
    }
    if (colored) {
      project.warnings.add("Basic block colors are not imported");
    }
  }

  private static Location location(ByteBuffer b, R2Project project) throws IOException {
    Location location = new Location(b.getInt(), b.getLong());
    int id = location.module();
    require(id == -1 || (id >= 0 && id < project.modules.size()), "Invalid module index");
    if (id != -1) {
      Mapping module = project.modules.get(id);
      require(
          Long.compareUnsigned(location.delta(), module.vmax() - module.vmin()) <= 0,
          "Address outside module");
    }
    return location;
  }

  private static int count(ByteBuffer b, int minimumSize) throws IOException {
    int count = b.getInt();
    require(count >= 0 && count <= b.remaining() / minimumSize, "Invalid record count");
    return count;
  }

  private static String string(ByteBuffer strings, int offset) throws IOException {
    if (offset == -1) {
      return null;
    }
    require(offset >= 0 && offset < strings.limit(), "Invalid string offset");
    int end = offset;
    while (end < strings.limit() && strings.get(end) != 0) {
      end++;
    }
    require(end < strings.limit(), "Unterminated string");
    return StandardCharsets.UTF_8.decode(strings.slice(offset, end - offset)).toString();
  }

  private static String requiredString(ByteBuffer strings, int offset) throws IOException {
    require(offset != -1, "Missing required string");
    return string(strings, offset);
  }

  private static void require(boolean condition, String message) throws IOException {
    if (!condition) {
      throw new IOException(message);
    }
  }

  /** Encode analysis as an RPRJ v6 file. The string table follows all referring sections. */
  public static byte[] write(R2Project project) throws IOException {
    Strings strings = new Strings();
    Output out = new Output();
    out.u32(MAGIC);
    out.u32(VERSION);
    Output info = new Output();
    info.u32(strings.add(project.name));
    info.u32(strings.add(project.user));
    info.u64(project.time);
    out.section(INFO, info);
    out.section(MAPS, writeMappings(project.maps, strings));
    out.section(MODS, writeMappings(project.modules, strings));
    Output flags = new Output();
    flags.u32(project.flags.size());
    for (Flag flag : project.flags) {
      require(flag.size() >= 0 && flag.size() <= 0xffffffffL, "Flag size exceeds uint32");
      require(flag.extras().size() == 7, "Flag requires seven optional extra fields");
      flags.u32(strings.add(flag.name()));
      flags.location(flag.location());
      flags.u32((int) flag.size());
      int bits = flag.demangled() ? 128 : 0;
      for (int i = 0; i < 7; i++) {
        if (flag.extras().get(i) != null) {
          bits |= 1 << i;
        }
      }
      flags.write(bits);
      for (String extra : flag.extras()) {
        if (extra != null) {
          flags.u32(strings.add(extra));
        }
      }
    }
    out.section(FLAG, flags);
    Output comments = new Output();
    for (Comment comment : project.comments) {
      comments.u32(strings.add(comment.text()));
      comments.location(comment.location());
      comments.u64(comment.size());
    }
    out.section(CMNT, comments);
    out.section(FUNC, writeFunctions(project.functions, strings));
    Output xrefs = new Output();
    xrefs.u32(project.xrefs.size());
    for (Xref xref : project.xrefs) {
      xrefs.location(xref.from());
      xrefs.location(xref.to());
      xrefs.u32(xref.type());
    }
    out.section(XREF, xrefs);
    out.section(STRS, strings.data);
    byte[] data = out.toByteArray();
    read(data); // Validate caller-supplied module references and ranges too.
    return data;
  }

  private static Output writeMappings(List<Mapping> mappings, Strings strings) throws IOException {
    Output out = new Output();
    for (Mapping mapping : mappings) {
      out.u32(strings.add(mapping.name()));
      out.u32(strings.add(mapping.file()));
      out.u64(mapping.pmin());
      out.u64(mapping.pmax());
      out.u64(mapping.vmin());
      out.u64(mapping.vmax());
      out.u32(mapping.attributes());
    }
    return out;
  }

  private static Output writeFunctions(List<Function> functions, Strings strings)
      throws IOException {
    Output out = new Output();
    out.u32(0); // No block colors.
    List<FunctionAttributes> attrs = new ArrayList<>();
    for (Function function : functions) {
      if (function.attributes() != null && !attrs.contains(function.attributes())) {
        attrs.add(function.attributes());
      }
    }
    out.u32(attrs.size());
    for (FunctionAttributes attr : attrs) {
      out.u32(strings.add(attr.callingConvention()));
      out.u32(attr.type());
      out.u32(attr.bits());
      out.u32(attr.flags());
      out.u64(attr.stack());
    }
    out.u32(functions.size());
    for (Function function : functions) {
      out.u32(strings.add(function.name()));
      out.location(function.location());
      out.u32(attrs.indexOf(function.attributes()));
      out.u32(function.blocks().size());
      out.u32(function.variables().size());
      for (Block block : function.blocks()) {
        out.location(block.location());
        out.u64(block.size());
        out.location(block.jump());
        out.location(block.fail());
        out.u32(-1);
      }
      for (Variable variable : function.variables()) {
        out.u32(strings.add(variable.name()));
        out.u32(strings.add(variable.type()));
        out.u32(variable.delta());
        out.write(variable.kind());
        out.write(variable.argument() ? 1 : 0);
        out.write(0);
        out.write(0);
      }
    }
    return out;
  }

  private static final class Strings {
    final Output data = new Output();
    final Map<String, Integer> offsets = new HashMap<>();

    Strings() throws IOException {
      add("");
    }

    int add(String value) throws IOException {
      if (value == null) {
        return -1;
      }
      require(value.indexOf('\0') < 0, "RPRJ strings cannot contain NUL");
      Integer offset = offsets.get(value);
      if (offset == null) {
        offset = data.size();
        data.writeBytes(value.getBytes(StandardCharsets.UTF_8));
        data.write(0);
        offsets.put(value, offset);
      }
      return offset;
    }
  }

  private static final class Output extends ByteArrayOutputStream {
    void u32(int value) {
      for (int i = 0; i < 4; i++) {
        write(value >>> (i * 8));
      }
    }

    void u64(long value) {
      for (int i = 0; i < 8; i++) {
        write((int) (value >>> (i * 8)));
      }
    }

    void location(Location location) {
      u32(location.module());
      u64(location.delta());
    }

    void section(int type, Output payload) {
      u32(payload.size() + 8);
      u32(type);
      writeBytes(payload.toByteArray());
    }
  }
}
