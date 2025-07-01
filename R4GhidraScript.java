/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Script to tap into Ghidra and control its commands through radare2 webserver.
//@category Functions
//
// Starts an http server to let r2 talk with us
// @author pancake <pancake@nopcode.org>
// @category integration
// @keybinding
// @menupath
// @toolbar
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.BlockModelService;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Stack;

public class GhidraR2WebServer extends GhidraScript {
  static GhidraR2WebServer ghidra = null;
  static HttpServer server = null;
  static int blocksize = 128;

  private static String hexAddress(Address addr) {
    return "0x" + String.format("%1$08x", addr.getUnsignedOffset());
  }

  private static String hexAddress(Long addr) {
    return "0x" + String.format("%1$08x", addr);
  }

  public String cmdAfb() {
    /*
    "f fcn.00000000 512 0x00000000"
    "af+ 0x00000000 fcn.00000000 f n"
    afc amd64 @ 0x00000000
    afB 64 @ 0x00000000
    afb+ 0x00000000 0x00000000 512 0xffffffffffffffff 0xffffffffffffffff n
    afS 0 @ 0x0
    */
    try {
      BlockModelService blockModelService = state.getTool().getService(BlockModelService.class);
      // CodeBlockModel cbm = blockModelService.getActiveSubroutineModel();
      CodeBlockModel cbm = blockModelService.getActiveBlockModel();
      CodeBlock[] blocks = cbm.getCodeBlocksContaining(ghidra.currentAddress, TaskMonitor.DUMMY);
      Function f = ghidra.getFunctionContaining(ghidra.currentAddress);
      Address faddr = f.getEntryPoint();
      StringBuffer sb = new StringBuffer();
      ArrayList<Address> fcnbbs = new ArrayList<Address>();
      Stack<Address> pending = new Stack<Address>();

      sb.append("af+ " + hexAddress(faddr) + " " + f.getName() + "\n");
      while (true) {
        for (CodeBlock block : blocks) {
          long addr = block.getMinAddress().getUnsignedOffset();
          long last = block.getMaxAddress().getUnsignedOffset(); // XXX this is the end of the function :(
	  // i cant find a way to get the basicblock size
          fcnbbs.add(block.getMinAddress());
          String jumpfail = "";
          CodeBlockReferenceIterator dst = block.getDestinations(TaskMonitor.DUMMY);
          if (dst.hasNext()) {
            CodeBlockReference destBlock = dst.next();
            Address jaddr = destBlock.getDestinationAddress();
            jumpfail += " " + hexAddress(jaddr);
            if (!fcnbbs.contains(jaddr)) {
              pending.push(jaddr);
            }
          }
          long size = last - addr + 1;
          sb.append(
              "afb+"
                  + " "
                  + hexAddress(faddr)
                  + " "
                  + hexAddress(addr)
                  + " "
                  + hexAddress(size)
                  + jumpfail
                  + "\n");
        }
        if (pending.size() > 0) {
          Address poppedAddress = pending.pop();
          blocks = cbm.getCodeBlocksContaining(poppedAddress, TaskMonitor.DUMMY);
        } else {
          break;
        }
      }
      return sb.toString();
    } catch (Exception e) {
      return e.toString();
    }
  }

  static class MyRootHandler implements HttpHandler {
    public void handle(HttpExchange t) throws IOException {
      try {
        byte[] response = "".getBytes();
        t.sendResponseHeaders(200, response.length);
        OutputStream os = t.getResponseBody();
        os.write(response);
        os.close();
      } catch (Exception e) {
        ghidra.println(e.toString());
      }
    }
  }

  static class MyCmdHandler implements HttpHandler {
    private String cmdAf(String arg) {
      char rad = (arg.indexOf("*") != -1) ? '*' : ' ';
      // Function f = ghidra.getFunctionAt(ghidra.currentAddress);
      Function f = ghidra.getFunctionContaining(ghidra.currentAddress);
      if (f == null) {
        return "Cannot find function at " + ghidra.currentAddress + "\n";
      }
      try {
        Variable[] vars = f.getAllVariables();
        String comment = f.getComment();
        StringBuffer sb = new StringBuffer();
        Address addr = f.getEntryPoint();
        if (comment != null) {
          String b64comment = Base64.getEncoder().encodeToString(comment.getBytes());
          sb.append(String.format("CCu base64:%s @ 0x%x\n", b64comment, addr));
        }
        sb.append("?e Done\n");
        return sb.toString();
      } catch (Exception e) {
        return e.toString() + "\n";
      }
    }

    private String cmdPdd(String arg) {
      char rad = (arg.indexOf("*") != -1) ? '*' : ' ';
      Integer len = 0;
      try{
        len = Integer.parseInt(arg.split(" ")[1]);
      }catch(Exception e){ } // TODO remove Pokemon handler
        
      // Function f = ghidra.getFunctionAt(ghidra.currentAddress);
      try{
        Function f = ghidra.getFunctionContaining(ghidra.currentAddress);
        return ghidra.decompile(f, rad);
      }catch(MemoryAccessException mae){
        return "FF".repeat(len);
      } catch (Exception e) {
        return e.toString() + "\n";
      }
    }

    private String showUsage() {
      StringBuffer msg = new StringBuffer("Usage: [ghidra-r2web-command .. args]\n");
      msg.append("?             - show this help message\n");
      msg.append("?V            - show Ghidra Version information\n");
      msg.append("?p [vaddr]    - get physical address for given virtual address\n");
      msg.append("f [name]      - set flag to the current offset inside ghidra (label)\n");
      msg.append("i             - show program information (arch/bits/hash..)\n");
      msg.append("/ [string]    - search for given string (which may contain \\x hex)\n");
      msg.append("s ([addr])    - check or set current seek address\n");
      msg.append("b ([bsize])   - get or set blocksize\n");
      msg.append("CC [comment]  - add or replace comment in current offset\n");
      msg.append("Cs            - define a string in the current address\n");
      msg.append("Cd            - define a dword in the current address\n");
      msg.append("aa            - analyze all the program\n");
      msg.append("af            - analyze function in current address\n");
      msg.append("afi           - get current function information\n");
      msg.append("af*           - get current function basic blocks as r2 commands\n");
      msg.append("afl           - list all functions analyzed by Ghidra\n");
      msg.append("px            - print Hexdump\n");
      msg.append("pdd           - print decompilation of current function\n");
      msg.append("pdd*          - decompile current function as comments for r2\n");
      msg.append("q             - quit the ghidra-r2web-server script\n");
      return msg.toString();
    }

    private String cmdPrint8(String arg) {
      int len = Integer.parseInt(arg);
      if (len < 1) {
        len = blocksize;
      }
      StringBuffer sb = new StringBuffer();
      try {
        byte[] bytes = ghidra.getBytes(ghidra.currentAddress, len);
        for (int i = 0; i < bytes.length; i++) {
          String b = Integer.toHexString(0x100 | (int) (bytes[i] & 0xff)).substring(1);
          sb.append(b);
        }
      } catch (Exception e) {
        sb.append(e.toString());
      }
      return sb.toString() + "\n";
    }

    String runCommand(String cmd) {
      ghidra.println("ORIGINAL COMMAND: " + cmd);
      int tmpAddr = cmd.indexOf('@');
      if (tmpAddr != -1) {
          Address origAddress = ghidra.currentAddress;
          long dec = Long.decode(cmd.substring(tmpAddr + 1));
          String addr = "0x" + Long.toHexString(dec);
          ghidra.currentAddress = ghidra.parseAddress(addr);
          ghidra.goTo(ghidra.currentAddress);
          cmd = cmd.substring(0, tmpAddr);
          ghidra.println("ADDRESS: " + addr +" = "+ ghidra.currentAddress.toString());
      }
      ghidra.println("COMMAND: " + cmd);
      
      if (cmd.length() == 0) {
        return "Unknown ghidra-r2web-server command.";
      }
      switch (cmd.charAt(0)) {
        case '/':
          if (cmd.length() > 1) {
            switch (cmd.charAt(1)) {
              case ' ':
                Address[] res = ghidra.findBytes(ghidra.currentAddress, cmd.substring(2), 9999);
                String out = "";
                for (Address a : res) {
                  out += a.toString() + "\n";
                }
                return out;
              case 'x':
                return "Usage: / \\xAA\\xBB instead";
            }
          }
          return "Usage: '/ string' or '/x [hex]'";
        case 'a':
          if (cmd.equals("aa")) {
            Program program = ghidra.getCurrentProgram();
            ghidra.analyzeAll(program);
          } else if (cmd.equals("af*")) {
            return ghidra.cmdAfb();
          } else if (cmd.equals("afi*")) {
            return ghidra.cmdAfb();
          } else if (cmd.equals("afb")) {
            return ghidra.cmdAfb();
          } else if (cmd.equals("afi")) {
            try {
              // Function f = ghidra.getFunctionAt(ghidra.currentAddress);
              Function f = ghidra.getFunctionContaining(ghidra.currentAddress);
              StringBuffer sb = new StringBuffer();
              sb.append("name: " + f.getName() + "\n");
              sb.append("addr: " + f.getEntryPoint().toString() + "\n");
              sb.append("frame: " + f.getStackPurgeSize() + "\n");
              for (Parameter p : f.getParameters()) {
                sb.append("arg: " + p.toString() + "\n");
              }
              sb.append("sig: " + f.getSignature() + "\n");
              sb.append("ret: " + f.getReturn().toString() + "\n");
              for (Variable p : f.getLocalVariables()) {
                sb.append("var: " + p.toString() + "\n");
              }
              sb.append("noreturn: " + f.hasNoReturn() + "\n");
              sb.append("vararg: " + f.hasVarArgs() + "\n");
              sb.append("inline: " + f.isInline() + "\n");
              sb.append("thunk: " + f.isThunk() + "\n");
              sb.append("external: " + f.isExternal() + "\n");
              sb.append("global: " + f.isGlobal() + "\n");
              return sb.toString();
            } catch (Exception e) {
              return e.toString();
            }
          } else if (cmd.startsWith("afl")) {
            boolean rad = cmd.indexOf("*") != -1;
            Function f = ghidra.getFirstFunction();
            StringBuffer sb = new StringBuffer();
            while (f != null) {
              if (rad) {
                sb.append("f ghi." + f.getName() + " 1 0x" + f.getEntryPoint() + "\n");
              } else {
                sb.append(hexAddress(f.getEntryPoint()) + "  " + f.getName() + "\n");
              }
              f = ghidra.getFunctionAfter(f);
            }
            return sb.toString();
          } else if (cmd.equals("af")) {
            Address addr = ghidra.currentAddress;
            // ghidra.addEntrypoint(addr);
            ghidra.disassemble(addr);
            ghidra.createFunction(addr, "ghidra." + addr.toString());
            return cmdAf(cmd);
          } else if (cmd.startsWith("af-")) {
            ghidra.removeFunctionAt(ghidra.currentAddress);
            return "";
          }
          return "See afl";
        case '?':
          if (cmd.length() > 1) {
            switch (cmd.charAt(1)) {
              case 'V':
                return ghidra.getGhidraVersion() + "\n";
              case 'p':
                Address at = null;
                try {
                  at = ghidra.currentAddress.getAddress(cmd.substring(2));
                } catch (Exception e) {
                }
                if (at == null) {
                  at = ghidra.currentAddress;
                }
                return hexAddress(at.getPhysicalAddress()) + "\n";
            }
          }
          return showUsage();
        case 'f':
          if (cmd.length() > 1 && cmd.charAt(1) == ' ') {
            try {
              String comment = cmd.substring(2);
              ghidra.createLabel(ghidra.currentAddress, comment, false);
            } catch (Exception e) {
              return e.toString();
            }
            return "";
          }
          return "";
        case 'i':
          // "is"
          // SymbolTable  program.getSymbolTable()
          // "iD"
          // java.lang.String  getDemangled​(java.lang.String mangled)
          if (cmd.equals("is")) {
            return runCommand("afl*");
          }
          Program program = ghidra.getCurrentProgram();
          Language l = program.getLanguage();
          String processor = l.getProcessor().toString().toLowerCase();
          // TODO: incomplete
          String arch = "x86";
          String bits = "64";
          if (processor.equals("aarch64")) {
            arch = "arm";
            bits = "64";
          } else if (processor.indexOf("arm") != -1) {
            arch = "arm";
            bits = "32";
          }
          String res = "e asm.arch=" + arch + "\n";
          res += "e asm.bits=" + bits + "\n";
          res += "f base.addr=0x" + program.getImageBase() + "\n";
          res += "# cpu " + processor + "\n";
          res += "# md5 " + program.getExecutableMD5() + "\n";
          res += "# exe " + program.getExecutablePath() + "\n";
          return res;
        case 'C': // "C"
          try {
            if (cmd.length() > 1) {
              switch (cmd.charAt(1)) {
                case 's': // "Cs"
                  ghidra.createAsciiString(ghidra.currentAddress);
                  break;
                case 'd': // "Cd"
                  ghidra.createWord(ghidra.currentAddress);
                  break;
                case 'C': // "CC"
                  if (cmd.length() > 2 && cmd.charAt(2) == ' ') {
                    ghidra.println("Set comment");
                    ghidra.setPreComment(ghidra.currentAddress, cmd.substring(3));
                    return "";
                  }
                  ghidra.println("List comment");
                  return allComments();
              }
            }
          } catch (Exception e) {
            return e.toString();
          }
          return "Usage: CC [comment] @ addr";
        case 's': // "s"
          if (cmd.length() > 1 && cmd.charAt(1) == ' ') {
            Address seekAddr= ghidra.parseAddress(cmd.substring(2));
            ghidra.goTo(seekAddr); // goTo doesn't update currentAddress!
            ghidra.currentAddress=seekAddr;
          }
          return hexAddress(ghidra.currentAddress) + "\n";
        case 'p':
          if (cmd.length() > 1) {
            switch (cmd.charAt(1)) {
              case 'x': // "px"
                break;
              case '8': // "p8"
                return cmdPrint8(cmd.substring(2).trim());
              case 'd': // "pdd" and "pdd*"
                return cmdPdd(cmd.substring(2).trim());
                // TODO
              default:
                return "Usage: p[x8d]";
            }
          }
          break;
        case 'x': // "x"
          StringBuffer sb = new StringBuffer();
          try {
            byte[] bytes = ghidra.getBytes(ghidra.currentAddress, blocksize);
            for (int i = 0; i < bytes.length; i++) {
              sb.append(" " + bytes[i]);
            }
          } catch (Exception e) {
            sb.append(e.toString());
          }
          return sb.toString() + "\n";
        case 'b':
          if (cmd.length() > 1 && cmd.charAt(1) == ' ') {
            blocksize = Integer.parseInt(cmd.substring(2));
            return "";
          }
          return "" + blocksize + "\n";
        case 'q':
          server.stop(0);
          server = null;
          return "quit";
        default:
          return showUsage();
      }
      return cmd;
    }

    public String allComments() {
      StringBuffer sb = new StringBuffer();
      MemoryBlock[] blocks = ghidra.getMemoryBlocks();

      // iterate through all memory blocks in current program
      for (int i = 0; i < blocks.length; i++) {
        // iterate through all addresses for current block
        MemoryBlock m = blocks[i];
        ghidra.println("Scanning block beginning at 0x" + m.getStart().toString());
        Address a;
        for (a = m.getStart(); !a.equals(m.getEnd().add(1)); a = a.add(1)) {
          String curComment;

          // replace target with replacement within each comment at address
          curComment = ghidra.getEOLComment(a);
          if (curComment != null) {
            sb.append("   0x" + a.toString() + ":  " + curComment + "\n");
            // setEOLComment(a, newComment);
          }
          /*
                    curComment = getPlateComment(a);
                    if (curComment != null) {
                      sb.append("   0x" + a.toString() + ":  " + curComment + "\n");
                      // setPlateComment(a, newComment);
                    }
                    curComment = getPostComment(a);
                    if (curComment != null) {
                      sb.append("   0x" + a.toString() + ":  " + curComment + "\n");
                      // setPostComment(a, newComment);
                    }
                    curComment = getPreComment(a);
                    if (curComment != null) {
                      sb.append("   0x" + a.toString() + ":  " + curComment + "\n");
                      // setPreComment(a, newComment);
                    }
          */
        }
      }
      return sb.toString();
    }

    public void handle(HttpExchange t) throws IOException {
      // query must be urlencoded
      String cmd = t.getRequestURI().getPath().toString().substring(5);
      try {
        byte[] response = runCommand(cmd).getBytes();
        t.sendResponseHeaders(200, response.length);
        OutputStream os = t.getResponseBody();
        os.write(response);
        os.close();
      } catch (Exception e) {
        ghidra.println(e.toString());
      }
    }
  }

  public void run() throws Exception {
    this.ghidra = this;
    String portString = askString("r2web HTTP Server", "Port", "9191");
    int port = Integer.parseInt(portString);
    if (port < 1) {
      port = 9191;
    }
    // port = askInt("ghidra r2web server", "Port number");
    server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/", new MyRootHandler());
    server.createContext("/cmd", new MyCmdHandler());
    server.setExecutor(null); // creates a default executor
    server.start();
    println("Run this line to stop the server: 'curl http://localhost:" + port + "/cmd/q'");
    boolean res =
        askYesNo(
            "Do you want to stop the ghidra-r2web-server webserver?",
            "$ r2 r2web://localhost:"
                + port
                + "/cmd/\nPress yes to stop the server.\nPress 'no' to continue in background (EXPERIMENTAL)");
    if (res) {
      // to run in background just comment this line,
      // but if the script is changed we cant shut it
      // down until we close Ghidra completely
      server.stop(0);
    }
  }

  public String decompile(Function f, char rad) throws Exception {
    StringBuffer sb = new StringBuffer();

    // Stop after this headless script
    // setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

    DecompInterface di = new DecompInterface();
    println("Simplification style: " + di.getSimplificationStyle()); // DEBUG
    println("Debug enables: " + di.debugEnabled());

    println(String.format("Decompiling %s() at 0x%s", f.getName(), f.getEntryPoint().toString()));

    println("Program: " + di.openProgram(f.getProgram())); // DEBUG

    // Decompile with a 5-seconds timeout
    DecompileResults dr = di.decompileFunction(f, 5, null);
    println("Decompilation completed: " + dr.decompileCompleted()); // DEBUG

    DecompiledFunction df = dr.getDecompiledFunction();
    println(df.getC());

    // Print lines prepend with addresses
    PrettyPrinter pp = new PrettyPrinter(f, dr.getCCodeMarkup(), new IdentityNameTransformer());
    ArrayList<ClangLine> lines = new ArrayList<ClangLine>(pp.getLines());

    for (ClangLine line : lines) {
      long minAddress = Long.MAX_VALUE;
      long maxAddress = 0;
      for (int i = 0; i < line.getNumTokens(); i++) {
        if (line.getToken(i).getMinAddress() == null) {
          continue;
        }
        long addr = line.getToken(i).getMinAddress().getOffset();
        minAddress = addr < minAddress ? addr : minAddress;
        maxAddress = addr > maxAddress ? addr : maxAddress;
      }
      String codeline = line.toString();
      int colon = codeline.indexOf(':');
      if (colon != -1) {
        codeline = codeline.substring(colon + 1);
        codeline = line.getIndentString() + codeline;
      }
      if (rad == '*') {
        String b64comment = Base64.getEncoder().encodeToString(codeline.getBytes());
        sb.append(String.format("CCu base64:%s @ 0x%x\n", b64comment, minAddress));
      } else {
        if (maxAddress == 0) {
          String msg = String.format("           %s\n", codeline);
          sb.append(msg);
        } else {
          String msg = hexAddress(minAddress) + " " + codeline + "\n";
          sb.append(msg);
        }
      }
    }
    return sb.toString();
  }
}
