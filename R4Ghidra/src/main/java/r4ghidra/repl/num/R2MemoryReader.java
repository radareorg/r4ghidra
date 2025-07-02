package r4ghidra.repl.num;

/**
 * Interface for reading memory values in R2Num expressions.
 *
 * <p>This interface allows external components to provide memory access functionality for bracketed
 * expressions like [addr:size].
 */
public interface R2MemoryReader {
/**
* Read a value from memory at the specified address with the given size
*
* @param address The memory address to read from
* @param size The size of the memory read in bytes
* @param littleEndian Whether to use little endian byte order
* @return The value read from memory
* @throws Exception If the memory access fails
*/
long readMemory(long address, int size, boolean littleEndian) throws Exception;
}
