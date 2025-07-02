package r4ghidra;

import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;

public class R2InfoCmd extends R2CmdHandler {

@Override
public boolean canHandle(char cmdChar) {
	if (cmdChar == 'i') return true;
	return false;
}

@Override
public String handle(String cmd) {
	/*if (cmd.equals("is")) {
		return runCommand("afl*");
	}*/
	Program program = R4GhidraState.api.getCurrentProgram();
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
}
}
