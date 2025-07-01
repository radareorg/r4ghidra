package r4ghidra;

import java.util.Arrays;
import java.util.List;

public class R2CreateCmd extends R2CmdHandler {
	List<R2CmdHandler> handlers;

	public R2CreateCmd() {
		this(0);
	}

	public R2CreateCmd(int pos) {
		cmdPos = pos;
		handlers = Arrays.asList(new R2CreateCommentCmd(cmdPos + 1), new R2CreateDwordCmd(cmdPos + 1),
				new R2CreateStringCmd(cmdPos + 1));
	}

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 'C')
			return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
		for (R2CmdHandler h : handlers) {
			if (h.canHandle(cmd)) {
				return h.handle(cmd);
			}
		}
		return "";
	}

}
