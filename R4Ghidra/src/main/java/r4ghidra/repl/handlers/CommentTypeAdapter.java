package r4ghidra.repl.handlers;

/**
 * Adapter class to handle different versions of CommentType between Ghidra versions. This addresses
 * compatibility issues between Ghidra 11.3 and 11.4 where CommentType may have changed from a class
 * with constants to an enum.
 */
public class CommentTypeAdapter {
// Comment type constants
/**
 * End-of-line comment type (value 0)
 */
public static final int EOL = 0;
/**
 * Pre comment type (value 1)
 */
public static final int PRE = 1;
/**
 * Post comment type (value 2)
 */
public static final int POST = 2;
/**
 * Plate comment type (value 3)
 */
public static final int PLATE = 3;
/**
 * Repeatable comment type (value 4)
 */
public static final int REPEATABLE = 4;

// Cached CommentType object for EOL comments
private static Object eolCommentType = null;

/**
* Get the appropriate CommentType object/enum for the current Ghidra version
*
* @param commentTypeValue The integer value representing the comment type
* @return The appropriate CommentType object for the current Ghidra version
*/
public static Object getCommentType(int commentTypeValue) {
	// For EOL comments, use cached value if available
	if (commentTypeValue == EOL && eolCommentType != null) {
	return eolCommentType;
	}

	Object result = null;

	try {
	// First try the enum approach (Ghidra 11.4+)
	Class<?> commentTypeClass = Class.forName("ghidra.program.model.listing.CommentType");
	Object[] enumConstants = commentTypeClass.getEnumConstants();

	if (enumConstants != null && commentTypeValue < enumConstants.length) {
		// CommentType is an enum in this version
		result = enumConstants[commentTypeValue];
	} else {
		// Fall back to constants approach (Ghidra 11.3 and earlier)
		switch (commentTypeValue) {
		case EOL:
			result = commentTypeClass.getField("EOL").get(null);
			break;
		case PRE:
			result = commentTypeClass.getField("PRE").get(null);
			break;
		case POST:
			result = commentTypeClass.getField("POST").get(null);
			break;
		case PLATE:
			result = commentTypeClass.getField("PLATE").get(null);
			break;
		case REPEATABLE:
			result = commentTypeClass.getField("REPEATABLE").get(null);
			break;
		}
	}
	} catch (Exception e) {
	// If all attempts fail, return null
	return null;
	}

	// Cache EOL comment type for future use
	if (commentTypeValue == EOL) {
	eolCommentType = result;
	}

	return result;
}
}
