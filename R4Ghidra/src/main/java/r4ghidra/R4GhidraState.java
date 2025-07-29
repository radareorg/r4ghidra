package r4ghidra;

import ghidra.app.services.CodeViewerService;
import ghidra.program.flatapi.FlatProgramAPI;

/**
 * Shared state for R4Ghidra
 *
 * <p>This class provides static variables to maintain global state across the R4Ghidra plugin.
 * Note: This is suitable for a proof-of-concept implementation. For a more robust solution,
 * consider adding proper validation, thread safety, and encapsulation.
 */
public class R4GhidraState {
  /** Reference to the Ghidra program API */
  public static FlatProgramAPI api = null;
  public static CodeViewerService codeViewer = null;

}
