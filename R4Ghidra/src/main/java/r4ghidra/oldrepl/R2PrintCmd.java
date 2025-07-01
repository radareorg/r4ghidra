package r4ghidra;

import java.util.Arrays;
import java.util.List;

public class R2PrintCmd extends R2CmdHandler {
	List<R2CmdHandler> handlers ;
	R2PrintCmd(){
		this(0);
	}
	public R2PrintCmd(int i) {
		cmdPos=i;
		handlers = Arrays.asList(new R2PddCmd(cmdPos+1), new R2P8Cmd(cmdPos+1), new R2PrintHexCmd(cmdPos+1));
	}
	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 'p') return true;
		return false;
	}
	
	private R2CmdHandler findHandler(String cmd) {
		for (R2CmdHandler h: handlers) {
			if (h.canHandle(cmd)) {
				return h;
			}
		}
		return null;
	}
	
	@Override
	public String handle(String cmd) {
		R2CmdHandler h = findHandler(cmd);
		if (h == null) {
			return "Subhandler not found!";
		}
		
		return h.handle(cmd);
	}

}
