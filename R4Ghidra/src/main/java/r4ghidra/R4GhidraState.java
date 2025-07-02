package r4ghidra;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;

/*
 * This is good enough for a PoC. Long term we may have to consider validation, threads etc.
 * */
public class R4GhidraState {
public static Address r2Seek = null;
public static FlatProgramAPI api = null;
public static int blockSize = 128;
}
