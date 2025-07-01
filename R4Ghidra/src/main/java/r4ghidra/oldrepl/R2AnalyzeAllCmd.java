package r4ghidra;

public class R2AnalyzeAllCmd extends R2CmdHandler {
	public R2AnalyzeAllCmd(){}
	public R2AnalyzeAllCmd(int pos){
		cmdPos = pos;
	}
	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 'a') return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
		// TODO do we need a transaction here?
		R4GhidraState.api.analyzeAll(R4GhidraState.api.getCurrentProgram());
		return "Analysis complete";
	}

}
