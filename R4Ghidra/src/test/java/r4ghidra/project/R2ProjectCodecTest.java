package r4ghidra.project;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import r4ghidra.project.R2Project.*;

/** Dependency-free codec regression tests; run with make test-project. */
public class R2ProjectCodecTest {
  public static void main(String[] args) throws Exception {
    R2Project project = sample();
    byte[] encoded = R2ProjectCodec.write(project);
    R2Project decoded = R2ProjectCodec.read(encoded);
    check(project.name.equals(decoded.name) && project.time == decoded.time, "info roundtrip");
    check(
        project.modules.equals(decoded.modules) && project.maps.equals(decoded.maps),
        "mapping roundtrip");
    check(project.flags.equals(decoded.flags), "flag extras, uint32 size and UTF-8 roundtrip");
    check(project.comments.equals(decoded.comments), "comment roundtrip");
    check(
        project.functions.equals(decoded.functions), "functions, blocks, attributes and variables");
    check(project.xrefs.equals(decoded.xrefs), "xref roundtrip");
    check(
        decoded.resolve(new Location(0, 0x10)) == 0xffff800000000010L,
        "unsigned address resolution");

    byte[] v5 = encoded.clone();
    buffer(v5).putInt(4, 5);
    check(R2ProjectCodec.read(v5).flags.equals(project.flags), "version 5 compatibility");
    byte[] future = encoded.clone();
    buffer(future).putInt(4, 7);
    invalid(future);
    byte[] magic = encoded.clone();
    magic[0] = 0;
    invalid(magic);
    byte[] size = encoded.clone();
    buffer(size).putInt(8, -1);
    invalid(size);
    buffer(size).putInt(8, 7);
    invalid(size);
    for (int length = 0; length < encoded.length; length++) {
      invalid(Arrays.copyOf(encoded, length));
    }
    int flag = section(encoded, 2);
    byte[] count = encoded.clone();
    buffer(count).putInt(flag, -1);
    invalid(count);
    byte[] string = encoded.clone();
    buffer(string).putInt(flag + 4, 0xfffffffe);
    invalid(string);
    buffer(string).putInt(flag + 4, -1);
    invalid(string);
    byte[] module = encoded.clone();
    buffer(module).putInt(flag + 8, 50);
    invalid(module);
    byte[] delta = encoded.clone();
    buffer(delta).putLong(flag + 12, 0x200);
    invalid(delta);
    byte[] termination = encoded.clone();
    termination[termination.length - 1] = 1;
    invalid(termination);
    invalid(Arrays.copyOf(encoded, encoded.length + 1));
    byte[] duplicate = Arrays.copyOf(encoded, encoded.length + 8);
    buffer(duplicate).putInt(encoded.length, 8).putInt(encoded.length + 4, 1);
    invalid(duplicate);
    System.out.println("RPRJ codec regression tests passed");

    if (args.length == 2) {
      R2Project nativeProject = R2ProjectCodec.read(Files.readAllBytes(Path.of(args[0])));
      check(
          nativeProject.flags.stream().anyMatch(f -> f.name().equals("test.flag")),
          "radare2 flag import");
      check(
          nativeProject.comments.stream().anyMatch(c -> c.text().equals("native comment")),
          "radare2 comment import");
      check(
          nativeProject.functions.stream()
              .anyMatch(f -> f.name().equals("test.func") && !f.blocks().isEmpty()),
          "radare2 function import");
      check(!nativeProject.xrefs.isEmpty(), "radare2 reference import");
      Files.write(Path.of(args[1]), R2ProjectCodec.write(nativeProject));
      System.out.println("Read native radare2 project and wrote Java project");
    }
  }

  static R2Project sample() {
    R2Project project = new R2Project();
    project.name = "test project";
    project.user = "test";
    project.time = 123456789;
    Mapping mapping =
        new Mapping(
            ".text", "/tmp/test.bin", 0, 255, 0xffff800000000000L, 0xffff8000000000ffL, 0x12345678);
    project.modules.add(mapping);
    project.maps.add(
        new Mapping(mapping.name(), mapping.file(), 0, 255, mapping.vmin(), mapping.vmax(), 5));
    project.flags.add(
        new Flag(
            "test.λ",
            new Location(0, 0x10),
            0xffffffffL,
            Arrays.asList("symbols", "real name", null, "uint64_t", "red", "flag comment", "alias"),
            true));
    project.flags.add(new Flag("absolute", Location.absolute(0x1234), 0));
    project.comments.add(new Comment("multiline\nкомментарий", new Location(0, 0x14), 1));
    project.functions.add(
        new R2Project.Function(
            "function",
            new Location(0, 0x20),
            new FunctionAttributes("sysv", 1, 64, 1, 32),
            List.of(
                new Block(new Location(0, 0x20), 8, Location.absolute(-1), new Location(0, 0x28))),
            List.of(new Variable("local", "int", -8, 'b', false))));
    project.xrefs.add(new Xref(new Location(0, 0x20), new Location(0, 0x10), 'd' | (4 << 8)));
    return project;
  }

  private static int section(byte[] data, int type) {
    ByteBuffer b = buffer(data);
    for (int at = 8; at < data.length; at += b.getInt(at)) {
      if (b.getInt(at + 4) == type) {
        return at + 8;
      }
    }
    throw new AssertionError("Missing section " + type);
  }

  private static ByteBuffer buffer(byte[] data) {
    return ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
  }

  private static void invalid(byte[] data) throws Exception {
    try {
      R2ProjectCodec.read(data);
      throw new AssertionError("Malformed project accepted (length " + data.length + ")");
    } catch (IOException expected) {
      // Expected rejection through the public API, rather than an unchecked exception.
    }
  }

  static void check(boolean value, String message) {
    if (!value) {
      throw new AssertionError(message);
    }
  }
}
