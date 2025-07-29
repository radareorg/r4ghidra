package r4ghidra;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;

/**
 * Shared state for R4Ghidra
 * <p>
 * This class provides static variables to maintain global state across the R4Ghidra plugin.
 * Note: This is suitable for a proof-of-concept implementation. For a more robust solution,
 * consider adding proper validation, thread safety, and encapsulation.
 */
public class R4GhidraState {
  /** Current address (seek) in the R2 context */
  public static Address r2Seek = null;
  /** Reference to the Ghidra program API */
  public static FlatProgramAPI api = null;
  /** Current block size for memory operations */
  public static int blockSize = 128;
}
