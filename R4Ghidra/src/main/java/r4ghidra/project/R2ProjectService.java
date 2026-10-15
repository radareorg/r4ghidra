package r4ghidra.project;

import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.*;
import r4ghidra.project.R2Project.*;
import r4ghidra.repl.R2Context;

/** Transfers binary project analysis to/from an already loaded Ghidra program. */
public final class R2ProjectService {
  private R2ProjectService() {}

  public record Result(int flags, int comments, int functions, int xrefs, List<String> warnings) {
    public String describe() {
      String text =
          String.format(
              "%d flags, %d comments, %d functions, %d references\n",
              flags, comments, functions, xrefs);
      return warnings.isEmpty() ? text : text + String.join("\n", warnings) + "\n";
    }
  }

  /** Merge analysis in a single undoable transaction. Files referenced by MAPS are never opened. */
  public static Result importProject(
      Program program, R2Context context, byte[] data, TaskMonitor monitor)
      throws IOException, CancelledException {
    R2Project project = R2ProjectCodec.read(data);
    Set<String> warnings = new LinkedHashSet<>(project.warnings);
    Resolver resolver = new Resolver(program, project, warnings, monitor);
    int flags = 0, comments = 0, functions = 0, xrefs = 0;
    List<Flag> importedFlags = new ArrayList<>();
    List<Long> flagAddresses = new ArrayList<>();
    int transaction = program.startTransaction("Import radare2 binary project");
    boolean commit = false;
    try {
      for (Flag flag : project.flags) {
        monitor.checkCancelled();
        Address address = resolver.address(flag.location());
        if (address == null || !program.getMemory().contains(address)) {
          warnings.add("Skipped flags outside program memory");
          continue;
        }
        String name = symbolName(flag.name());
        if (program.getSymbolTable().getGlobalSymbol(name, address) == null) {
          program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
        }
        importedFlags.add(flag);
        flagAddresses.add(address.getOffset());
        if (flag.demangled() || flag.extras().stream().anyMatch(Objects::nonNull)) {
          warnings.add(
              "Flag extras (spaces, aliases, real names, types, colors and flag comments) are not"
                  + " imported");
        }
        flags++;
      }
      for (Comment comment : project.comments) {
        monitor.checkCancelled();
        Address address = resolver.address(comment.location());
        if (address == null || !program.getMemory().contains(address)) {
          warnings.add("Skipped comments outside program memory");
          continue;
        }
        program.getListing().setComment(address, CodeUnit.EOL_COMMENT, comment.text());
        comments++;
      }
      for (R2Project.Function function : project.functions) {
        monitor.checkCancelled();
        Address entry = resolver.address(function.location());
        if (entry == null || !program.getMemory().contains(entry)) {
          warnings.add("Skipped functions outside program memory");
          continue;
        }
        AddressSet body = new AddressSet(entry);
        for (Block block : function.blocks()) {
          Address start = resolver.address(block.location());
          if (block.size() == 0) {
            continue;
          }
          if (start == null || block.size() < 0) {
            throw new IOException("Invalid function block range");
          }
          Address end = start.addNoWrap(block.size() - 1);
          if (!program.getMemory().contains(start, end)) {
            throw new IOException("Function block outside program memory: " + start);
          }
          body.add(start, end);
        }
        ghidra.program.model.listing.Function existing =
            program.getFunctionManager().getFunctionAt(entry);
        String name = symbolName(function.name());
        if (existing == null) {
          existing =
              program.getFunctionManager().createFunction(name, entry, body, SourceType.IMPORTED);
        } else {
          existing.setName(name, SourceType.IMPORTED);
          if (!function.blocks().isEmpty()) {
            existing.setBody(body);
          }
        }
        if (existing == null) {
          throw new IOException("Cannot create function at " + entry);
        }
        if (function.attributes() != null) {
          existing.setNoReturn((function.attributes().flags() & 1) != 0);
          FunctionAttributes attrs = function.attributes();
          if (attrs.callingConvention() != null || attrs.stack() != 0) {
            warnings.add("Function calling conventions and stack frames are not imported");
          }
        }
        if (!function.variables().isEmpty()) {
          warnings.add(
              "Function variables are not imported (radare2 and Ghidra use different storage"
                  + " conventions)");
        }
        functions++;
      }
      for (Xref xref : project.xrefs) {
        monitor.checkCancelled();
        Address from = resolver.address(xref.from());
        Address to = resolver.address(xref.to());
        if (from == null
            || to == null
            || !program.getMemory().contains(from)
            || !program.getMemory().contains(to)) {
          warnings.add("Skipped references outside program memory");
          continue;
        }
        program
            .getReferenceManager()
            .addMemoryReference(from, to, refType(xref.type()), SourceType.IMPORTED, -1);
        xrefs++;
      }
      monitor.checkCancelled();
      commit = true;
    } catch (CancelledException | IOException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException("Cannot import RPRJ analysis: " + e.getMessage(), e);
    } finally {
      program.endTransaction(transaction, commit);
    }
    // Update transient REPL flags only after the program transaction succeeds.
    if (context != null) {
      String space = context.getCurrentFlagspace();
      context.setFlagspace("*");
      try {
        for (int i = 0; i < importedFlags.size(); i++) {
          Flag flag = importedFlags.get(i);
          context.setFlag(
              flag.name(),
              flagAddresses.get(i),
              (int) Math.max(1, Math.min(Integer.MAX_VALUE, flag.size())));
          if (flag.size() == 0 || flag.size() > Integer.MAX_VALUE) {
            warnings.add("REPL flag sizes are limited to 1..2147483647 bytes");
          }
        }
      } finally {
        context.setFlagspace(space);
      }
    }
    return new Result(flags, comments, functions, xrefs, new ArrayList<>(warnings));
  }

  /** Snapshot mapped memory, labels/REPL flags, EOL comments, function blocks, and references. */
  public static R2Project exportProject(Program program, R2Context context, TaskMonitor monitor)
      throws IOException, CancelledException {
    R2Project project = new R2Project();
    project.name = program.getName();
    project.user = System.getProperty("user.name", "");
    project.time = System.currentTimeMillis() * 1000;
    collectMappings(program, project, monitor);
    Set<String> flags = new HashSet<>();
    if (context != null) {
      Map<String, Integer> sizes = context.getFlagSizes();
      for (Map.Entry<String, Long> flag : context.getFlags().entrySet()) {
        project.flags.add(
            new Flag(
                flag.getKey(),
                project.locate(flag.getValue()),
                sizes.getOrDefault(flag.getKey(), 1)));
        flags.add(flag.getKey() + "@" + flag.getValue());
      }
    }
    SymbolIterator symbols = program.getSymbolTable().getAllSymbols(false);
    while (symbols.hasNext()) {
      monitor.checkCancelled();
      Symbol symbol = symbols.next();
      if (!symbol.getAddress().isMemoryAddress()
          || symbol.getAddress().getAddressSpace().isOverlaySpace()
          || !(symbol.getSymbolType() == SymbolType.LABEL
              || symbol.getSymbolType() == SymbolType.FUNCTION)) {
        continue;
      }
      String name = symbol.getName(true);
      long offset = symbol.getAddress().getOffset();
      if (flags.add(name + "@" + offset)) {
        project.flags.add(new Flag(name, project.locate(offset), 1));
      }
    }
    AddressIterator comments =
        program
            .getListing()
            .getCommentAddressIterator(CodeUnit.EOL_COMMENT, program.getMemory(), true);
    while (comments.hasNext()) {
      monitor.checkCancelled();
      Address address = comments.next();
      if (exportable(program, address)) {
        project.comments.add(
            new Comment(
                program.getListing().getComment(CodeUnit.EOL_COMMENT, address),
                project.locate(address.getOffset()),
                1));
      }
    }
    BasicBlockModel model = new BasicBlockModel(program);
    FunctionIterator functions = program.getFunctionManager().getFunctions(true);
    while (functions.hasNext()) {
      monitor.checkCancelled();
      ghidra.program.model.listing.Function function = functions.next();
      if (!exportable(program, function.getEntryPoint())) {
        continue;
      }
      List<Block> blocks = new ArrayList<>();
      CodeBlockIterator iterator = model.getCodeBlocksContaining(function.getBody(), monitor);
      AddressSet covered = new AddressSet();
      while (iterator.hasNext()) {
        CodeBlock block = iterator.next();
        Location jump = Location.absolute(-1), fail = Location.absolute(-1);
        CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
        while (destinations.hasNext()) {
          CodeBlockReference ref = destinations.next();
          if (ref.getFlowType().isJump() && exportable(program, ref.getDestinationAddress())) {
            jump = project.locate(ref.getDestinationAddress().getOffset());
          } else if (ref.getFlowType().isFallthrough()
              && exportable(program, ref.getDestinationAddress())) {
            fail = project.locate(ref.getDestinationAddress().getOffset());
          }
        }
        AddressRangeIterator ranges = function.getBody().intersect(block).getAddressRanges();
        while (ranges.hasNext()) {
          AddressRange range = ranges.next();
          blocks.add(
              new Block(
                  project.locate(range.getMinAddress().getOffset()),
                  range.getLength(),
                  jump,
                  fail));
          covered.add(range);
        }
      }
      // Functions without disassembly still need a body in the exported project.
      AddressRangeIterator missing = function.getBody().subtract(covered).getAddressRanges();
      while (missing.hasNext()) {
        AddressRange range = missing.next();
        blocks.add(
            new Block(
                project.locate(range.getMinAddress().getOffset()),
                range.getLength(),
                Location.absolute(-1),
                Location.absolute(-1)));
      }
      FunctionAttributes attrs =
          new FunctionAttributes(
              null, 1, program.getDefaultPointerSize() * 8, function.hasNoReturn() ? 1 : 0, 0);
      String variableWarning =
          "Function variables are not exported (radare2 and Ghidra use different storage"
              + " conventions)";
      if (function.getAllVariables().length != 0 && !project.warnings.contains(variableWarning)) {
        project.warnings.add(variableWarning);
      }
      project.functions.add(
          new R2Project.Function(
              function.getName(true),
              project.locate(function.getEntryPoint().getOffset()),
              attrs,
              blocks,
              List.of()));
    }
    ReferenceManager references = program.getReferenceManager();
    AddressIterator sources = references.getReferenceSourceIterator(program.getMemory(), true);
    Set<String> seen = new HashSet<>();
    while (sources.hasNext()) {
      monitor.checkCancelled();
      for (Reference ref : references.getReferencesFrom(sources.next())) {
        if (!ref.isMemoryReference()
            || !exportable(program, ref.getFromAddress())
            || !exportable(program, ref.getToAddress())) {
          continue;
        }
        int type = refType(ref.getReferenceType());
        String key = ref.getFromAddress() + ":" + ref.getToAddress() + ":" + type;
        if (seen.add(key)) {
          project.xrefs.add(
              new Xref(
                  project.locate(ref.getFromAddress().getOffset()),
                  project.locate(ref.getToAddress().getOffset()),
                  type));
        }
      }
    }
    return project;
  }

  private static boolean exportable(Program program, Address address) {
    return address.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())
        && program.getMemory().contains(address);
  }

  private static String symbolName(String name) throws IOException {
    if (name == null || name.isBlank()) {
      throw new IOException("Missing project symbol name");
    }
    return SymbolUtilities.replaceInvalidChars(name, true);
  }

  private static RefType refType(int type) {
    return switch (type & 255) {
      case 'C' -> RefType.UNCONDITIONAL_CALL;
      case 'c', 'j', 'i' -> RefType.UNCONDITIONAL_JUMP;
      default ->
          (type & (2 << 8)) != 0
              ? ((type & (4 << 8)) != 0 ? RefType.READ_WRITE : RefType.WRITE)
              : ((type & (4 << 8)) != 0 ? RefType.READ : RefType.DATA);
    };
  }

  private static int refType(RefType type) {
    if (type.isCall()) {
      return 'C' | (1 << 8);
    }
    if (type.isJump()) {
      return 'c' | (1 << 8);
    }
    return 'd' | (type.isRead() ? 4 << 8 : 0) | (type.isWrite() ? 2 << 8 : 0);
  }

  private static void collectMappings(Program program, R2Project project, TaskMonitor monitor)
      throws CancelledException, IOException {
    for (MemoryBlock block : program.getMemory().getBlocks()) {
      monitor.checkCancelled();
      if (!exportable(program, block.getStart())) {
        project.warnings.add(
            "Skipped memory outside the default address space: " + block.getName());
        continue;
      }
      long physical = 0;
      String file = null;
      if (block.getSourceInfos().size() == 1) {
        MemoryBlockSourceInfo source = block.getSourceInfos().get(0);
        if (source.getFileBytes().isPresent() && source.getFileBytesOffset() >= 0) {
          physical = source.getFileBytes().get().getFileOffset() + source.getFileBytesOffset();
          file = program.getExecutablePath();
          if (file == null || file.isEmpty()) {
            file = source.getFileBytes().get().getFilename();
          }
        }
      }
      long start = block.getStart().getOffset(), end = block.getEnd().getOffset();
      int permissions =
          (block.isRead() ? 4 : 0) | (block.isWrite() ? 2 : 0) | (block.isExecute() ? 1 : 0);
      project.modules.add(
          new Mapping(
              block.getName(),
              file,
              physical,
              physical + block.getSize() - 1,
              start,
              end,
              checksum(program, block.getStart(), block.getSize())));
      // Anonymous/BSS blocks have module bounds but no file-backed MAPS record.
      if (file != null) {
        project.maps.add(
            new Mapping(
                block.getName(),
                file,
                physical,
                physical + block.getSize() - 1,
                start,
                end,
                permissions));
      }
    }
  }

  /** Same sampled checksum as rprj_checksum in newprj/maps.inc.c. */
  private static int checksum(Program program, Address start, long size) throws IOException {
    int length = (int) Math.min(1024, size);
    long last = size - length;
    long[] samples = {0, Math.min(size / 2, last), last};
    int checksum = 0;
    byte[] data = new byte[length];
    try {
      for (int i = 0; i < samples.length; i++) {
        if (i > 0 && samples[i] == samples[i - 1]) {
          continue;
        }
        int read = program.getMemory().getBytes(start.add(samples[i]), data);
        checksum ^= (int) samples[i];
        for (int j = 0; j < read; j++) {
          checksum = (checksum << 1) ^ Byte.toUnsignedInt(data[j]) ^ (checksum & 1);
        }
      }
    } catch (MemoryAccessException e) {
      return 0; // Uninitialized memory has no checksum.
    }
    return checksum;
  }

  private static final class Resolver {
    private final Program program;
    private final long[] bases;

    Resolver(Program program, R2Project project, Set<String> warnings, TaskMonitor monitor)
        throws IOException, CancelledException {
      this.program = program;
      bases = new long[project.modules.size()];
      R2Project current = new R2Project();
      collectMappings(program, current, monitor);
      for (int i = 0; i < bases.length; i++) {
        Mapping saved = project.modules.get(i);
        Mapping best = null;
        int bestScore = 0;
        boolean ambiguous = false;
        for (Mapping candidate : current.modules) {
          if (saved.vmax() - saved.vmin() != candidate.vmax() - candidate.vmin()) {
            continue;
          }
          int score = 0;
          if (saved.attributes() != 0 && saved.attributes() == candidate.attributes()) {
            score += 100;
          }
          if (saved.name() != null && saved.name().equals(candidate.name())) {
            score += 60;
          }
          if (saved.file() != null
              && candidate.file() != null
              && basename(saved.file()).equals(basename(candidate.file()))
              && saved.pmin() == candidate.pmin()) {
            score += 60;
          }
          if (score > bestScore) {
            bestScore = score;
            best = candidate;
            ambiguous = false;
          } else if (score == bestScore) {
            ambiguous = true;
          }
        }
        bases[i] = saved.vmin();
        if (bestScore >= 60 && !ambiguous) {
          bases[i] = best.vmin();
        } else {
          warnings.add(
              "No unique memory match for module " + saved.name() + "; using its saved addresses");
        }
      }
    }

    Address address(Location location) {
      long value =
          location.module() == -1 ? location.delta() : bases[location.module()] + location.delta();
      if (location.module() == -1 && value == -1L) {
        return null;
      }
      try {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
      } catch (AddressOutOfBoundsException e) {
        return null;
      }
    }

    private static String basename(String file) {
      return file.substring(Math.max(file.lastIndexOf('/'), file.lastIndexOf('\\')) + 1);
    }
  }
}
