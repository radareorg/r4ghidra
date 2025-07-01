package ghidrar2web.repl.num;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.program.model.address.Address;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidrar2web.repl.R2Context;

/**
 * Ghidra implementation of R2MemoryReader interface.
 * 
 * This class uses the Ghidra API to read memory for bracket expressions
 * in R2Num evaluations.
 */
public class R2GhidraMemoryReader implements R2MemoryReader {
    private R2Context context;
    
    /**
     * Create a new Ghidra memory reader with the specified context
     * 
     * @param context The R2Context to use for memory access
     */
    public R2GhidraMemoryReader(R2Context context) {
        this.context = context;
    }
    
    /**
     * Read memory value using Ghidra API
     */
    @Override
    public long readMemory(long address, int size, boolean littleEndian) throws Exception {
        FlatProgramAPI api = context.getAPI();
        if (api == null) {
            throw new Exception("FlatProgramAPI not available in context");
        }
        
        // Convert the address to a Ghidra Address
        Address addr = api.toAddr(address);
        
        // Read the bytes from memory
        byte[] bytes = new byte[size];
        int bytesRead = api.getBytes(addr, bytes);
        
        if (bytesRead != size) {
            throw new Exception("Failed to read " + size + " bytes at address " + addr);
        }
        
        // Convert bytes to a long value based on size and endianness
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        
        switch (size) {
            case 1:
                return buffer.get() & 0xFFL;
            case 2:
                return buffer.getShort() & 0xFFFFL;
            case 4:
                return buffer.getInt() & 0xFFFFFFFFL;
            case 8:
                return buffer.getLong();
            default:
                throw new Exception("Invalid memory read size: " + size);
        }
    }
}