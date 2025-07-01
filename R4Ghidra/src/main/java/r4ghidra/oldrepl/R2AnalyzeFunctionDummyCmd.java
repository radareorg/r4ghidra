package r4ghidra;

import java.util.ArrayList;
import java.util.Stack;

import ghidra.app.services.BlockModelService;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.util.task.TaskMonitor;

// TODO This probably needs to be refactored to separate classes
public class R2AnalyzeFunctionDummyCmd extends R2CmdHandler {
	public R2AnalyzeFunctionDummyCmd(){
		this(0);
	}
	public R2AnalyzeFunctionDummyCmd(int pos){
		cmdPos = pos;
	}
	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == '*' || cmdChar == 'i' || cmdChar == 'b')
			return true;
		return false;
	}

	private String cmdAfb(String cmd) {
	    /*
	    "f fcn.00000000 512 0x00000000"
	    "af+ 0x00000000 fcn.00000000 f n"
	    afc amd64 @ 0x00000000
	    afB 64 @ 0x00000000
	    afb+ 0x00000000 0x00000000 512 0xffffffffffffffff 0xffffffffffffffff n
	    afS 0 @ 0x0
	    */
		FlatProgramAPI ghidra = R4GhidraState.api;
		Address currentAddress = R4GhidraState.r2Seek;
		try {
			CodeBlockModel cbm = new BasicBlockModel(ghidra.getCurrentProgram());// blockModelService.getActiveBlockModel();
			CodeBlock[] blocks = cbm.getCodeBlocksContaining(currentAddress, TaskMonitor.DUMMY);
			Function f = ghidra.getFunctionContaining(currentAddress);
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
					sb.append("afb+" + " " + hexAddress(faddr) + " " + hexAddress(addr) + " " + hexAddress(size)
							+ jumpfail + "\n");
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

	private String handleI(String cmd) {
		if (cmd.length() > cmdPos+1 && cmd.charAt(cmdPos + 1) == '*')
			return cmdAfb(cmd);
		try {
			FlatProgramAPI ghidra = R4GhidraState.api;
			Address currentAddress = R4GhidraState.r2Seek;
			// Function f = ghidra.getFunctionAt(ghidra.currentAddress);
			Function f = ghidra.getFunctionContaining(currentAddress);
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

	}

	@Override
	public String handle(String cmd) {
		if (cmd.charAt(cmdPos) == 'i')
			return handleI(cmd);
		return cmdAfb(cmd);
	}

}
