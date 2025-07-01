package r4ghidra;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;

public class R2AnalyzeFunctionList extends R2CmdHandler {
	public R2AnalyzeFunctionList(){
		this(0);
	}
	public R2AnalyzeFunctionList(int pos){
		cmdPos = pos;
	}

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 'l' ) return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
        boolean rad = cmd.indexOf("*") != -1;
        FlatProgramAPI ghidra = R4GhidraState.api;
        
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

	}

}
