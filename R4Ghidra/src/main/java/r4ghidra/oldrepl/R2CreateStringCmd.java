package r4ghidra;

public class R2CreateStringCmd extends R2CmdHandler {
	public R2CreateStringCmd(){
		this(0);
	}
	public R2CreateStringCmd(int pos){
		cmdPos = pos;
	}

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 's') return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
		try {
        	R4GhidraState.api.start();
			R4GhidraState.api.createAsciiString(R4GhidraState.r2Seek);
			R4GhidraState.api.end(true);
			return "";
        } catch (Exception e) {
			R4GhidraState.api.end(false);
			return e.getMessage();
		}
	}

}
