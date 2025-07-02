package r4ghidra.repl.filesystem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import r4ghidra.repl.R2Context;

/**
 * Implementation of the R2FileSystem interface with sandbox support
 *
 * <p>This class provides methods for interacting with files, with support for sandboxed access and
 * in-memory files. The sandbox settings in the R2Context are used to determine which operations are
 * allowed.
 */
public class R2SandboxedFileSystem implements R2FileSystem {

// Context with sandbox settings
private R2Context context;

// In-memory files ($-prefixed)
private Map<String, String> memoryFiles;

/**
* Create a new R2SandboxedFileSystem
*
* @param context The R2 context with sandbox settings
*/
public R2SandboxedFileSystem(R2Context context) {
	this.context = context;
	this.memoryFiles = new HashMap<>();
}

@Override
public String readFile(String path) throws IOException, R2FileSystemException {
	// Check if it's an in-memory file
	if (isMemoryFile(path)) {
	return readMemoryFile(path);
	}

	// Check sandbox permissions for file read
	if (context.isSandboxed(R2Context.R_SANDBOX_GRAIN_FILES)) {
	throw new R2FileSystemException("File reading not allowed by sandbox settings");
	}

	// Proceed with regular file read
	Path filePath = Paths.get(path);
	return Files.readString(filePath);
}

@Override
public void writeFile(String path, String content) throws IOException, R2FileSystemException {
	// Check if it's an in-memory file
	if (isMemoryFile(path)) {
	writeMemoryFile(path, content);
	return;
	}

	// Check sandbox permissions for disk write
	if (context.isSandboxed(R2Context.R_SANDBOX_GRAIN_DISK)) {
	throw new R2FileSystemException("Disk writing not allowed by sandbox settings");
	}

	// Check sandbox permissions for file write
	if (context.isSandboxed(R2Context.R_SANDBOX_GRAIN_FILES)) {
	throw new R2FileSystemException("File writing not allowed by sandbox settings");
	}

	// Proceed with regular file write
	Path filePath = Paths.get(path);

	// Create parent directories if needed
	Path parent = filePath.getParent();
	if (parent != null) {
	Files.createDirectories(parent);
	}

	Files.writeString(filePath, content);
}

@Override
public void appendFile(String path, String content) throws IOException, R2FileSystemException {
	// Check if it's an in-memory file
	if (isMemoryFile(path)) {
	appendMemoryFile(path, content);
	return;
	}

	// Check sandbox permissions for disk write
	if (context.isSandboxed(R2Context.R_SANDBOX_GRAIN_DISK)) {
	throw new R2FileSystemException("Disk writing not allowed by sandbox settings");
	}

	// Check sandbox permissions for file write
	if (context.isSandboxed(R2Context.R_SANDBOX_GRAIN_FILES)) {
	throw new R2FileSystemException("File writing not allowed by sandbox settings");
	}

	// Proceed with regular file append
	Path filePath = Paths.get(path);

	// Create parent directories if needed
	Path parent = filePath.getParent();
	if (parent != null) {
	Files.createDirectories(parent);
	}

	// Use append option when writing
	Files.writeString(filePath, content, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
}

@Override
public void deleteFile(String path) throws IOException, R2FileSystemException {
	// Check if it's an in-memory file
	if (isMemoryFile(path)) {
	deleteMemoryFile(path);
	return;
	}

	// Check sandbox permissions for disk write
	if (context.isSandboxed(R2Context.R_SANDBOX_GRAIN_DISK)) {
	throw new R2FileSystemException("Disk modifications not allowed by sandbox settings");
	}

	// Check sandbox permissions for file write
	if (context.isSandboxed(R2Context.R_SANDBOX_GRAIN_FILES)) {
	throw new R2FileSystemException("File deletion not allowed by sandbox settings");
	}

	// Proceed with regular file delete
	Path filePath = Paths.get(path);
	Files.delete(filePath);
}

@Override
public boolean fileExists(String path) {
	// Check if it's an in-memory file
	if (isMemoryFile(path)) {
	return memoryFiles.containsKey(getMemoryFileName(path));
	}

	// For real files, check even with sandbox restrictions
	// (we're just checking, not actually accessing the file content)
	Path filePath = Paths.get(path);
	return Files.exists(filePath);
}

@Override
public List<String> listFiles(String path) throws IOException, R2FileSystemException {
	// Special case for listing memory files
	if (path.equals("$") || path.equals("$-")) {
	return listMemoryFiles();
	}

	// Check sandbox permissions for file listing
	if (context.isSandboxed(R2Context.R_SANDBOX_GRAIN_FILES)) {
	throw new R2FileSystemException("File listing not allowed by sandbox settings");
	}

	// Proceed with regular directory listing
	Path dirPath = Paths.get(path);

	try (Stream<Path> stream = Files.list(dirPath)) {
	return stream.map(Path::toString).collect(Collectors.toList());
	}
}

@Override
public List<String> listMemoryFiles() {
	return new ArrayList<>(memoryFiles.keySet());
}

@Override
public boolean isMemoryFile(String path) {
	return path != null && path.startsWith("$");
}

@Override
public String getMemoryFileName(String path) {
	if (path == null || !path.startsWith("$")) {
	return null;
	}
	return path.substring(1); // Remove the $ prefix
}

/**
* Read from an in-memory file
*
* @param path The path to the memory file (including $ prefix)
* @return The contents of the memory file
* @throws R2FileSystemException If the memory file doesn't exist
*/
private String readMemoryFile(String path) throws R2FileSystemException {
	String memoryFileName = getMemoryFileName(path);
	if (!memoryFiles.containsKey(memoryFileName)) {
	throw new R2FileSystemException("Memory file not found: " + path);
	}
	return memoryFiles.get(memoryFileName);
}

/**
* Write to an in-memory file
*
* @param path The path to the memory file (including $ prefix)
* @param content The content to write to the memory file
*/
private void writeMemoryFile(String path, String content) {
	String memoryFileName = getMemoryFileName(path);
	memoryFiles.put(memoryFileName, content);
}

/**
* Append to an in-memory file
*
* @param path The path to the memory file (including $ prefix)
* @param content The content to append to the memory file
* @throws R2FileSystemException If the memory file doesn't exist
*/
private void appendMemoryFile(String path, String content) throws R2FileSystemException {
	String memoryFileName = getMemoryFileName(path);
	if (!memoryFiles.containsKey(memoryFileName)) {
	// If it doesn't exist, create it
	memoryFiles.put(memoryFileName, content);
	} else {
	// If it exists, append to it
	String existingContent = memoryFiles.get(memoryFileName);
	memoryFiles.put(memoryFileName, existingContent + content);
	}
}

/**
* Delete an in-memory file
*
* @param path The path to the memory file (including $ prefix)
* @throws R2FileSystemException If the memory file doesn't exist
*/
private void deleteMemoryFile(String path) throws R2FileSystemException {
	String memoryFileName = getMemoryFileName(path);
	if (!memoryFiles.containsKey(memoryFileName)) {
	throw new R2FileSystemException("Memory file not found: " + path);
	}
	memoryFiles.remove(memoryFileName);
}
}
