# SynQ Version Pragma Documentation

## Overview

SynQ supports version pragmas similar to Solidity, allowing contracts to specify the compiler version they require. This prevents compilation with incompatible compiler versions and helps ensure contracts work as expected.

## Syntax

```synq
pragma synq ^1.0.0;
```

The version pragma must appear at the very top of your contract file, before any contract definitions.

## Supported Comparators

| Comparator | Description | Example |
|------------|-------------|---------|
| `^` | Compatible within same major version (recommended) | `^1.0.0` matches `>=1.0.0 <2.0.0` |
| `>=` | Greater than or equal | `>=1.0.0` matches `1.0.0` and above |
| `<=` | Less than or equal | `<=1.5.0` matches up to `1.5.0` |
| `>` | Greater than | `>1.0.0` matches above `1.0.0` |
| `<` | Less than | `<2.0.0` matches below `2.0.0` |
| `=` | Exact match | `=1.0.0` matches only `1.0.0` |

## Examples

### Basic Usage

```synq
pragma synq ^1.0.0;

contract MyContract {
    // Contract code
}
```

### Multiple Constraints

```synq
pragma synq >=1.0.0 <2.0.0;

contract MyContract {
    // Contract code
}
```

### Exact Version

```synq
pragma synq =1.0.0;

contract MyContract {
    // Contract code
}
```

## How It Works

1. **Parser**: The compiler parses the pragma statement and extracts version requirements
2. **Validation**: The compiler checks if its version satisfies the requirements
3. **Error**: If version is incompatible, compilation fails with a clear error message

## Version Number Format

Version numbers follow semantic versioning (semver):
- **Major.Minor.Patch** (e.g., `1.2.3`)
- **Major.Minor** (e.g., `1.2`) - patch defaults to `0`

## Best Practices

1. **Always Include**: Always include a version pragma in your contracts
2. **Use Caret**: Prefer `^` for flexibility while maintaining compatibility
3. **Test Compatibility**: Test your contracts with different compiler versions when possible
4. **Update When Needed**: Update the pragma when using new language features

## Error Messages

If the compiler version doesn't match the requirement, you'll see an error like:

```
Error: Compiler version 2.0.0 does not satisfy requirement ^1.0.0
Required: >=1.0.0 <2.0.0
```

## Migration Guide

### Adding to Existing Contracts

Simply add the pragma at the top:

```synq
// Before
contract MyContract {
    // ...
}

// After
pragma synq ^1.0.0;

contract MyContract {
    // ...
}
```

### From Solidity

If you're coming from Solidity, the syntax is very similar:

```solidity
// Solidity
pragma solidity ^0.8.0;
```

```synq
// SynQ
pragma synq ^1.0.0;
```

## Implementation Details

The version pragma is implemented in:
- **Grammar**: `synq.pest` - defines the syntax
- **Parser**: `parser.rs` - parses the pragma
- **Version Module**: `version.rs` - handles version comparison and validation

## Future Enhancements

Potential future enhancements:
- Support for multiple pragmas (e.g., experimental features)
- Version ranges with multiple constraints
- Automatic version detection from contract features
