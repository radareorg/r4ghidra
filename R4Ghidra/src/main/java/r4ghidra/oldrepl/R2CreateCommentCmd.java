package r4ghidra;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

public class R2CreateCommentCmd extends R2CmdHandler {
public R2CreateCommentCmd() {
	this(0);
}

public R2CreateCommentCmd(int pos) {
	cmdPos = pos;
}

@Override
public boolean canHandle(char cmdChar) {
	if (cmdChar == 'C') return true;
	return false;
}

private String allComments() {
	FlatProgramAPI api = R4GhidraState.api;
	StringBuffer sb = new StringBuffer();
	MemoryBlock[] blocks = api.getMemoryBlocks();

	// iterate through all memory blocks in current program
	for (int i = 0; i < blocks.length; i++) {
	// iterate through all addresses for current block
	MemoryBlock m = blocks[i];
	// ghidra.println("Scanning block beginning at 0x" + m.getStart().toString());
	Address a;
	for (a = m.getStart(); !a.equals(m.getEnd().add(1)); a = a.add(1)) {
		String curComment;

		// replace target with replacement within each comment at address
		curComment = api.getEOLComment(a);
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

@Override
public String handle(String cmd) {
	if (cmd.length() > 2 && cmd.charAt(2) == ' ') {
	R4GhidraState.api.start();
	R4GhidraState.api.setPreComment(R4GhidraState.r2Seek, cmd.substring(3));
	R4GhidraState.api.end(true);
	return "";
	}

	return allComments();
}
}
