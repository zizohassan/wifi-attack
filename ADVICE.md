# Code Review & Improvement Recommendations

## Critical Issues

### 1. Error Handling
- **Line 117, 367, 420**: Ignoring errors from `ReadString()` can cause silent failures
- **Line 254, 423**: Accessing `cmd.Process` without checking if process started successfully
- **Solution**: Always check errors and handle them appropriately

### 2. Resource Cleanup
- Monitor mode may not be restored if program crashes/interrupts
- Temporary files may not be cleaned up
- **Solution**: Use `defer` statements and signal handlers for cleanup

### 3. Process Management
- No check if `cmd.Process` is nil before calling `Kill()`
- **Solution**: Always verify process exists before operations

## Important Improvements

### 4. Configuration
- Hardcoded paths and values
- **Solution**: Use environment variables or config file

### 5. Input Validation
- No validation of BSSID format
- No sanitization of user input
- **Solution**: Add validation functions

### 6. Code Organization
- All logic in main.go
- **Solution**: Split into packages (scanner, capture, cracker, etc.)

### 7. Testing
- No unit tests
- **Solution**: Add tests for parsing, validation functions

## Best Practices

### 8. Context Usage
- Long-running operations should respect cancellation
- **Solution**: Use `context.Context` for cancellation

### 9. Logging
- Mix of `fmt.Println` and `log.Fatal`
- **Solution**: Use structured logging (logrus, zap, or stdlib log)

### 10. Constants
- Magic numbers throughout code
- **Solution**: Define constants at package level

## Specific Code Issues

### Line 254 - Process Kill
```go
// Current (unsafe):
cmd.Process.Kill()

// Should be:
if cmd.Process != nil {
    cmd.Process.Kill()
}
```

### Line 117 - Error Handling
```go
// Current:
input, _ := reader.ReadString('\n')

// Should be:
input, err := reader.ReadString('\n')
if err != nil {
    return "", fmt.Errorf("failed to read input: %w", err)
}
```

### CSV Parsing - Column Validation
- Assumes CSV format matches exactly
- No validation that columns exist
- Should validate header row matches expected format

## Suggested Refactoring

1. **Create a Config struct** for paths and settings
2. **Add signal handlers** for graceful shutdown
3. **Extract functions** into separate packages
4. **Add input validation** functions
5. **Use context** for cancellation
6. **Add unit tests** for parsing logic
7. **Improve error messages** with context

## Security Considerations

1. **Input Sanitization**: Validate all user inputs
2. **Path Traversal**: Ensure file paths are safe
3. **Privilege Escalation**: Check if running as root, warn if not
4. **Resource Limits**: Consider limiting concurrent operations

## Performance

1. **Buffering**: Consider buffered I/O for large files
2. **Goroutine Management**: Use sync.WaitGroup for goroutine coordination
3. **Memory**: Large CSV files could be streamed instead of loaded entirely
