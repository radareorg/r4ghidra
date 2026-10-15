package r4ghidra.repl.filesystem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
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
private Map<String, byte[]> memoryFiles;

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

	return Files.readString(checkedPath(path, false));
}

@Override
public byte[] readBytes(String path) throws IOException, R2FileSystemException {
	if (isMemoryFile(path)) {
		String name = getMemoryFileName(path);
		if (!memoryFiles.containsKey(name)) {
			throw new R2FileSystemException("Memory file not found: " + path);
		}
		return memoryFiles.get(name).clone();
	}
	return Files.readAllBytes(checkedPath(path, false));
}

@Override
public void writeBytes(String path, byte[] content) throws IOException, R2FileSystemException {
	if (isMemoryFile(path)) {
		memoryFiles.put(getMemoryFileName(path), content.clone());
		return;
	}
	Path filePath = checkedPath(path, true);
	if (filePath.getParent() != null) {
		Files.createDirectories(filePath.getParent());
	}
	Files.write(filePath, content);
}

@Override
public void writeFile(String path, String content) throws IOException, R2FileSystemException {
	// Check if it's an in-memory file
	if (isMemoryFile(path)) {
	writeMemoryFile(path, content);
	return;
	}

	Path filePath = checkedPath(path, true);

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

	Path filePath = checkedPath(path, true);

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

	Files.delete(checkedPath(path, true));
}

@Override
public boolean fileExists(String path) {
	// Check if it's an in-memory file
	if (isMemoryFile(path)) {
	return memoryFiles.containsKey(getMemoryFileName(path));
	}

	try {
	return Files.exists(checkedPath(path, false));
	} catch (IOException | R2FileSystemException e) {
	return false;
	}
}

@Override
public List<String> listFiles(String path) throws IOException, R2FileSystemException {
	// Special case for listing memory files
	if (path.equals("$") || path.equals("$-")) {
	return listMemoryFiles();
	}

	Path dirPath = checkedPath(path, false);

	try (Stream<Path> stream = Files.list(dirPath)) {
	return stream.filter(entry -> fileExists(entry.toString())).map(Path::toString).collect(Collectors.toList());
	}
}

/** Apply one policy to text, binary, metadata and script access, including symlink targets. */
private Path checkedPath(String path, boolean write) throws IOException, R2FileSystemException {
	int resources = R2Context.R_SANDBOX_GRAIN_FILES;
	if (write) {
	resources |= R2Context.R_SANDBOX_GRAIN_DISK;
	}
	if (context.isSandboxed(resources)) {
	throw new R2FileSystemException("File " + (write ? "writing" : "reading") + " not allowed by sandbox settings");
	}
	Path filePath = Paths.get(path);
	if (context.isSandboxed(R2Context.R_SANDBOX_GRAIN_HIDDEN)) {
	checkHiddenPath(filePath.toAbsolutePath());
	// Resolve the nearest existing ancestor as well, so an innocent-looking symlink cannot
	// expose a hidden target or create a new file inside a hidden directory.
	Path ancestor = filePath.toAbsolutePath();
	while (ancestor != null && !Files.exists(ancestor, LinkOption.NOFOLLOW_LINKS)) {
	ancestor = ancestor.getParent();
	}
	if (ancestor != null) {
	checkHiddenPath(ancestor.toRealPath());
	}
	}
	return filePath;
}

private void checkHiddenPath(Path path) throws R2FileSystemException {
	for (Path component : path) {
	String name = component.toString();
	if (name.startsWith(".") && !name.equals(".") && !name.equals("..")) {
	throw new R2FileSystemException("Hidden file access not allowed by sandbox settings");
	}
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
	return new String(memoryFiles.get(memoryFileName), StandardCharsets.UTF_8);
}

/**
* Write to an in-memory file
*
* @param path The path to the memory file (including $ prefix)
* @param content The content to write to the memory file
*/
private void writeMemoryFile(String path, String content) {
	String memoryFileName = getMemoryFileName(path);
	memoryFiles.put(memoryFileName, content.getBytes(StandardCharsets.UTF_8));
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
	memoryFiles.put(memoryFileName, content.getBytes(StandardCharsets.UTF_8));
	} else {
	// If it exists, append to it
	byte[] existingContent = memoryFiles.get(memoryFileName);
	byte[] suffix = content.getBytes(StandardCharsets.UTF_8);
	byte[] combined = java.util.Arrays.copyOf(existingContent, existingContent.length + suffix.length);
	System.arraycopy(suffix, 0, combined, existingContent.length, suffix.length);
	memoryFiles.put(memoryFileName, combined);
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
