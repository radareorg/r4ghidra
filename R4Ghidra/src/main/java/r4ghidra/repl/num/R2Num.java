package r4ghidra.repl.num;

import r4ghidra.repl.R2Context;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * R2Num - Implementation of radare2's RNum API for expression evaluation.
 * 
 * This class provides functionality for evaluating mathematical expressions
 * with support for:
 * - Different number bases (decimal, hexadecimal, octal, binary)
 * - Symbol resolution through callbacks
 * - Memory access with bracketed expressions
 * - Arithmetic operations
 * - Parenthesized expressions
 */
public class R2Num {
    // Default word size (in bytes)
    private static final int DEFAULT_WORD_SIZE = 4;
    
    // Context for configuration
    private R2Context context;
    
    // Callback for symbol resolution
    private R2NumCallback callback;
    
    // Memory reader for bracket expressions
    private R2MemoryReader memoryReader;
    
    // Configuration
    private boolean littleEndian = true;
    private int defaultSize = DEFAULT_WORD_SIZE;
    
    /**
     * Create a new R2Num instance with the specified context
     * 
     * @param context The R2Context for configuration
     */
    public R2Num(R2Context context) {
        this.context = context;
        this.littleEndian = true; // Default to little endian
        this.defaultSize = context.getBlockSize() > 0 ? context.getBlockSize() : DEFAULT_WORD_SIZE;
    }
    
    /**
     * Set the symbol resolution callback
     * 
     * @param callback The callback to use for resolving symbols
     */
    public void setCallback(R2NumCallback callback) {
        this.callback = callback;
    }
    
    /**
     * Set the memory reader for bracket expressions
     * 
     * @param reader The memory reader to use
     */
    public void setMemoryReader(R2MemoryReader reader) {
        this.memoryReader = reader;
    }
    
    /**
     * Configure the endianness
     * 
     * @param littleEndian true for little endian, false for big endian
     */
    public void setLittleEndian(boolean littleEndian) {
        this.littleEndian = littleEndian;
    }
    
    /**
     * Set the default size for memory reads
     * 
     * @param size The default size in bytes
     */
    public void setDefaultSize(int size) {
        this.defaultSize = size;
    }
    
    /**
     * Evaluate a numeric expression and return the result
     * 
     * @param expr The expression to evaluate
     * @return The result of the evaluation
     * @throws R2NumException If the expression cannot be evaluated
     */
    public long getValue(String expr) throws R2NumException {
        if (expr == null || expr.trim().isEmpty()) {
            return 0;
        }
        
        // Remove whitespace
        expr = expr.trim();
        
        try {
            // Tokenize and evaluate
            List<Token> tokens = tokenize(expr);
            return evaluateExpression(tokens);
        } catch (Exception e) {
            throw new R2NumException("Error evaluating expression: " + expr, e);
        }
    }
    
    /**
     * Token types for expression parsing
     */
    private enum TokenType {
        NUMBER, OPERATOR, OPEN_PAREN, CLOSE_PAREN, OPEN_BRACKET, CLOSE_BRACKET, SYMBOL
    }
    
    /**
     * Token class for parsed expression elements
     */
    private static class Token {
        TokenType type;
        String value;
        
        Token(TokenType type, String value) {
            this.type = type;
            this.value = value;
        }
        
        @Override
        public String toString() {
            return type + ":" + value;
        }
    }
    
    /**
     * Tokenize an expression into a list of tokens
     * 
     * @param expr The expression to tokenize
     * @return List of tokens
     * @throws R2NumException If tokenization fails
     */
    private List<Token> tokenize(String expr) throws R2NumException {
        List<Token> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inSymbol = false;
        
        for (int i = 0; i < expr.length(); i++) {
            char c = expr.charAt(i);
            
            // Handle bracket expressions specially
            if (c == '[') {
                // Process any accumulated token
                if (current.length() > 0) {
                    addToken(tokens, current.toString());
                    current.setLength(0);
                }
                
                // Find the matching closing bracket
                int depth = 1;
                int end = i + 1;
                while (end < expr.length() && depth > 0) {
                    char ch = expr.charAt(end);
                    if (ch == '[') depth++;
                    if (ch == ']') depth--;
                    end++;
                }
                
                if (depth > 0) {
                    throw new R2NumException("Unclosed bracket in expression: " + expr);
                }
                
                // Extract the bracket expression and add as a token
                String bracketExpr = expr.substring(i, end);
                tokens.add(new Token(TokenType.OPEN_BRACKET, bracketExpr));
                
                // Skip past the bracket expression
                i = end - 1;
                continue;
            }
            
            // Handle parentheses
            if (c == '(') {
                if (current.length() > 0) {
                    addToken(tokens, current.toString());
                    current.setLength(0);
                }
                tokens.add(new Token(TokenType.OPEN_PAREN, "("));
                continue;
            }
            
            if (c == ')') {
                if (current.length() > 0) {
                    addToken(tokens, current.toString());
                    current.setLength(0);
                }
                tokens.add(new Token(TokenType.CLOSE_PAREN, ")"));
                continue;
            }
            
            // Handle operators
            if (isOperator(c)) {
                // Special case for negative numbers
                if (c == '-' && (tokens.isEmpty() || 
                    (tokens.get(tokens.size() - 1).type == TokenType.OPERATOR) ||
                    (tokens.get(tokens.size() - 1).type == TokenType.OPEN_PAREN))) {
                    // This is a negative sign, not a subtraction operator
                    current.append(c);
                } else {
                    if (current.length() > 0) {
                        addToken(tokens, current.toString());
                        current.setLength(0);
                    }
                    tokens.add(new Token(TokenType.OPERATOR, String.valueOf(c)));
                }
                continue;
            }
            
            // Handle whitespace
            if (Character.isWhitespace(c)) {
                if (current.length() > 0) {
                    addToken(tokens, current.toString());
                    current.setLength(0);
                }
                continue;
            }
            
            // Accumulate current token
            current.append(c);
        }
        
        // Add the last token if there is one
        if (current.length() > 0) {
            addToken(tokens, current.toString());
        }
        
        return tokens;
    }
    
    /**
     * Add a token to the token list based on its type
     * 
     * @param tokens The list to add to
     * @param value The token value
     */
    private void addToken(List<Token> tokens, String value) {
        // Try to parse as a number
        if (isNumeric(value)) {
            tokens.add(new Token(TokenType.NUMBER, value));
        } else {
            // Otherwise it's a symbol
            tokens.add(new Token(TokenType.SYMBOL, value));
        }
    }
    
    /**
     * Check if a character is an operator
     * 
     * @param c The character to check
     * @return true if the character is an operator
     */
    private boolean isOperator(char c) {
        return c == '+' || c == '-' || c == '*' || c == '/' || c == '%' || 
               c == '&' || c == '|' || c == '^' || c == '~' || c == '>' || c == '<';
    }
    
    /**
     * Check if a string can be parsed as a number
     * 
     * @param str The string to check
     * @return true if the string is numeric
     */
    private boolean isNumeric(String str) {
        // Handle hex numbers (0x...)
        if (str.toLowerCase().startsWith("0x")) {
            try {
                Long.parseLong(str.substring(2), 16);
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        
        // Handle binary numbers (0b...)
        if (str.toLowerCase().startsWith("0b")) {
            try {
                Long.parseLong(str.substring(2), 2);
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        
        // Handle octal numbers (0...)
        if (str.length() > 1 && str.charAt(0) == '0' && Character.isDigit(str.charAt(1))) {
            try {
                Long.parseLong(str.substring(1), 8);
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        
        // Handle decimal numbers
        try {
            Long.parseLong(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
    
    /**
     * Evaluate a tokenized expression
     * 
     * @param tokens The tokens to evaluate
     * @return The result of the evaluation
     * @throws R2NumException If evaluation fails
     */
    private long evaluateExpression(List<Token> tokens) throws R2NumException {
        if (tokens == null || tokens.isEmpty()) {
            return 0;
        }
        
        // Convert infix notation to postfix (Shunting-yard algorithm)
        List<Token> postfix = infixToPostfix(tokens);
        
        // Evaluate the postfix expression
        return evaluatePostfix(postfix);
    }
    
    /**
     * Convert infix notation to postfix using the Shunting-yard algorithm
     * 
     * @param infix The infix tokens
     * @return The postfix tokens
     * @throws R2NumException If conversion fails
     */
    private List<Token> infixToPostfix(List<Token> infix) throws R2NumException {
        List<Token> postfix = new ArrayList<>();
        Stack<Token> operatorStack = new Stack<>();
        
        for (Token token : infix) {
            switch (token.type) {
                case NUMBER:
                    // Numbers go directly to the output
                    postfix.add(token);
                    break;
                
                case SYMBOL:
                    // Symbols are treated like numbers
                    postfix.add(token);
                    break;
                
                case OPEN_BRACKET:
                    // Evaluate the bracket expression separately
                    postfix.add(token);
                    break;
                
                case OPEN_PAREN:
                    // Push open parenthesis onto the operator stack
                    operatorStack.push(token);
                    break;
                
                case CLOSE_PAREN:
                    // Pop operators until we find the matching open parenthesis
                    while (!operatorStack.isEmpty() && operatorStack.peek().type != TokenType.OPEN_PAREN) {
                        postfix.add(operatorStack.pop());
                    }
                    
                    // Pop the open parenthesis
                    if (!operatorStack.isEmpty() && operatorStack.peek().type == TokenType.OPEN_PAREN) {
                        operatorStack.pop();
                    } else {
                        throw new R2NumException("Mismatched parentheses");
                    }
                    break;
                
                case OPERATOR:
                    // Pop operators with higher precedence
                    while (!operatorStack.isEmpty() && 
                           operatorStack.peek().type == TokenType.OPERATOR && 
                           getPrecedence(operatorStack.peek().value.charAt(0)) >= getPrecedence(token.value.charAt(0))) {
                        postfix.add(operatorStack.pop());
                    }
                    
                    // Push the current operator
                    operatorStack.push(token);
                    break;
                
                default:
                    throw new R2NumException("Unknown token type: " + token.type);
            }
        }
        
        // Pop any remaining operators
        while (!operatorStack.isEmpty()) {
            Token top = operatorStack.pop();
            if (top.type == TokenType.OPEN_PAREN) {
                throw new R2NumException("Mismatched parentheses");
            }
            postfix.add(top);
        }
        
        return postfix;
    }
    
    /**
     * Evaluate a postfix expression
     * 
     * @param postfix The postfix tokens
     * @return The result of evaluation
     * @throws R2NumException If evaluation fails
     */
    private long evaluatePostfix(List<Token> postfix) throws R2NumException {
        Stack<Long> valueStack = new Stack<>();
        
        for (Token token : postfix) {
            switch (token.type) {
                case NUMBER:
                    // Push the value onto the stack
                    valueStack.push(parseNumber(token.value));
                    break;
                
                case SYMBOL:
                    // Resolve the symbol and push its value
                    valueStack.push(resolveSymbol(token.value));
                    break;
                
                case OPEN_BRACKET:
                    // Evaluate the bracket expression and push its value
                    valueStack.push(evaluateBracketExpression(token.value));
                    break;
                
                case OPERATOR:
                    // Apply the operator to the top values on the stack
                    if (token.value.equals("~")) {
                        // Unary operator
                        if (valueStack.isEmpty()) {
                            throw new R2NumException("Not enough operands for operator: " + token.value);
                        }
                        
                        long operand = valueStack.pop();
                        valueStack.push(~operand);
                    } else {
                        // Binary operator
                        if (valueStack.size() < 2) {
                            throw new R2NumException("Not enough operands for operator: " + token.value);
                        }
                        
                        // Note: order matters for non-commutative operations
                        long operand2 = valueStack.pop();
                        long operand1 = valueStack.pop();
                        
                        long result;
                        char op = token.value.charAt(0);
                        
                        switch (op) {
                            case '+': result = operand1 + operand2; break;
                            case '-': result = operand1 - operand2; break;
                            case '*': result = operand1 * operand2; break;
                            case '/': 
                                if (operand2 == 0) {
                                    throw new R2NumException("Division by zero");
                                }
                                result = operand1 / operand2; 
                                break;
                            case '%': 
                                if (operand2 == 0) {
                                    throw new R2NumException("Modulo by zero");
                                }
                                result = operand1 % operand2; 
                                break;
                            case '&': result = operand1 & operand2; break;
                            case '|': result = operand1 | operand2; break;
                            case '^': result = operand1 ^ operand2; break;
                            case '>': result = operand1 >> operand2; break;
                            case '<': result = operand1 << operand2; break;
                            default:
                                throw new R2NumException("Unknown operator: " + op);
                        }
                        
                        valueStack.push(result);
                    }
                    break;
                
                default:
                    throw new R2NumException("Invalid token in postfix evaluation: " + token.type);
            }
        }
        
        if (valueStack.size() != 1) {
            throw new R2NumException("Invalid expression: too many values");
        }
        
        return valueStack.pop();
    }
    
    /**
     * Get the precedence of an operator
     * 
     * @param op The operator character
     * @return The precedence level (higher means higher precedence)
     */
    private int getPrecedence(char op) {
        switch (op) {
            case '~': return 4;  // Bitwise NOT (highest precedence)
            case '*': case '/': case '%': return 3;  // Multiplication, division, modulo
            case '+': case '-': return 2;  // Addition, subtraction
            case '<': case '>': return 1;  // Shifts
            case '&': case '|': case '^': return 0;  // Bitwise operations (lowest precedence)
            default: return -1;
        }
    }
    
    /**
     * Parse a number literal in various formats (hex, decimal, octal, binary)
     * 
     * @param numStr The number string to parse
     * @return The parsed numeric value
     * @throws R2NumException If parsing fails
     */
    private long parseNumber(String numStr) throws R2NumException {
        if (numStr == null || numStr.isEmpty()) {
            throw new R2NumException("Empty number string");
        }
        
        try {
            // Hexadecimal (0x prefix)
            if (numStr.toLowerCase().startsWith("0x")) {
                return Long.parseLong(numStr.substring(2), 16);
            }
            
            // Binary (0b prefix)
            if (numStr.toLowerCase().startsWith("0b")) {
                return Long.parseLong(numStr.substring(2), 2);
            }
            
            // Octal (0 prefix)
            if (numStr.length() > 1 && numStr.charAt(0) == '0' && Character.isDigit(numStr.charAt(1))) {
                return Long.parseLong(numStr.substring(1), 8);
            }
            
            // Decimal
            return Long.parseLong(numStr);
        } catch (NumberFormatException e) {
            throw new R2NumException("Invalid number format: " + numStr, e);
        }
    }
    
    /**
     * Resolve a symbol to its numeric value using the callback
     * 
     * @param symbol The symbol to resolve
     * @return The resolved value
     * @throws R2NumException If resolution fails
     */
    private long resolveSymbol(String symbol) throws R2NumException {
        if (callback == null) {
            throw new R2NumException("No symbol resolver callback set");
        }
        
        Long value = callback.resolveSymbol(symbol);
        if (value == null) {
            throw new R2NumException("Unable to resolve symbol: " + symbol);
        }
        
        return value;
    }
    
    /**
     * Read memory at the specified address with the given size
     * 
     * @param addr The address to read from
     * @param size The size in bytes to read
     * @return The value read from memory
     * @throws R2NumException If memory reading fails
     */
    private long readMemory(long addr, int size) throws R2NumException {
        if (memoryReader == null) {
            throw new R2NumException("No memory reader set");
        }
        
        try {
            return memoryReader.readMemory(addr, size, littleEndian);
        } catch (Exception e) {
            throw new R2NumException("Error reading memory at 0x" + Long.toHexString(addr), e);
        }
    }
    
    /**
     * Evaluate a bracket expression (memory read)
     * 
     * @param bracketExpr The bracket expression (e.g. "[main+4:4]")
     * @return The value read from memory
     * @throws R2NumException If evaluation fails
     */
    private long evaluateBracketExpression(String bracketExpr) throws R2NumException {
        if (bracketExpr == null || bracketExpr.length() < 2 || !bracketExpr.startsWith("[") || !bracketExpr.endsWith("]")) {
            throw new R2NumException("Invalid bracket expression: " + bracketExpr);
        }
        
        // Remove the surrounding brackets
        String expr = bracketExpr.substring(1, bracketExpr.length() - 1);
        
        // Check for size specification (:size)
        int size = defaultSize;
        String addrExpr = expr;
        
        int colonIndex = expr.lastIndexOf(':');
        if (colonIndex >= 0) {
            // Extract size
            String sizeStr = expr.substring(colonIndex + 1);
            addrExpr = expr.substring(0, colonIndex);
            
            try {
                size = Integer.parseInt(sizeStr);
                // Validate size (1, 2, 4, or 8 bytes)
                if (size != 1 && size != 2 && size != 4 && size != 8) {
                    throw new R2NumException("Invalid memory access size: " + size);
                }
            } catch (NumberFormatException e) {
                throw new R2NumException("Invalid size specification: " + sizeStr, e);
            }
        }
        
        // Evaluate the address expression
        long addr = getValue(addrExpr);
        
        // Read memory at the calculated address
        return readMemory(addr, size);
    }
}