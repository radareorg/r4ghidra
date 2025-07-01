package r4ghidra.repl.filesystem;

import java.io.IOException;
import java.util.List;

/**
 * Filesystem abstraction for the R2 REPL
 * 
 * This interface provides methods for interacting with files, with support for
 * sandboxed access and in-memory files.
 */
public interface R2FileSystem {
    
    /**
     * Read the contents of a file
     * 
     * @param path The path to the file to read
     * @return The contents of the file as a string
     * @throws IOException If the file cannot be read
     * @throws R2FileSystemException If the operation is not allowed by sandbox settings
     */
    String readFile(String path) throws IOException, R2FileSystemException;
    
    /**
     * Write to a file, overwriting any existing content
     * 
     * @param path The path to the file to write
     * @param content The content to write to the file
     * @throws IOException If the file cannot be written
     * @throws R2FileSystemException If the operation is not allowed by sandbox settings
     */
    void writeFile(String path, String content) throws IOException, R2FileSystemException;
    
    /**
     * Append to a file
     * 
     * @param path The path to the file to append to
     * @param content The content to append to the file
     * @throws IOException If the file cannot be appended to
     * @throws R2FileSystemException If the operation is not allowed by sandbox settings
     */
    void appendFile(String path, String content) throws IOException, R2FileSystemException;
    
    /**
     * Delete a file
     * 
     * @param path The path to the file to delete
     * @throws IOException If the file cannot be deleted
     * @throws R2FileSystemException If the operation is not allowed by sandbox settings
     */
    void deleteFile(String path) throws IOException, R2FileSystemException;
    
    /**
     * Check if a file exists
     * 
     * @param path The path to the file to check
     * @return true if the file exists, false otherwise
     */
    boolean fileExists(String path);
    
    /**
     * List all files in a directory
     * 
     * @param path The path to the directory to list
     * @return A list of file paths in the directory
     * @throws IOException If the directory cannot be read
     * @throws R2FileSystemException If the operation is not allowed by sandbox settings
     */
    List<String> listFiles(String path) throws IOException, R2FileSystemException;
    
    /**
     * List all in-memory files
     * 
     * @return A list of all in-memory file names (without the $ prefix)
     */
    List<String> listMemoryFiles();
    
    /**
     * Check if a path is an in-memory file (starts with $)
     * 
     * @param path The path to check
     * @return true if the path is an in-memory file, false otherwise
     */
    boolean isMemoryFile(String path);
    
    /**
     * Get the name of an in-memory file without the $ prefix
     * 
     * @param path The path to the in-memory file
     * @return The name of the file without the $ prefix
     */
    String getMemoryFileName(String path);
}