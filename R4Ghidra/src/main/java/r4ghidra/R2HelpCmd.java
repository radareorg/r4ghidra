package r4ghidra;

public class R2HelpCmd extends R2CmdHandler {
	public R2HelpCmd() {}

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == '?')
			return true;
		return false;
	}

	@Override
	public String handle(String cmd) {
		StringBuffer msg = new StringBuffer("Usage: [r4ghidra-command .. args]\n");
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
		msg.append("q             - quit the r4ghidra-server script\n");
		return msg.toString();
	}

}
