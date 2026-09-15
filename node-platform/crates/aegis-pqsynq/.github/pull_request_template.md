# Pull Request Security Checklist

## Security Review Required
- [ ] **Security Impact Assessment**: This PR has been assessed for security impact
- [ ] **Cryptographic Changes**: Any cryptographic changes have been reviewed by security team
- [ ] **Input Validation**: All inputs are properly validated
- [ ] **Error Handling**: Error handling does not leak sensitive information
- [ ] **Memory Management**: Sensitive data is properly zeroized
- [ ] **Dependencies**: New dependencies have been security reviewed

## Code Quality
- [ ] **Code Review**: Code has been reviewed by at least one other developer
- [ ] **Tests**: All tests pass and new tests have been added as needed
- [ ] **Documentation**: Documentation has been updated as needed
- [ ] **Performance**: Performance impact has been considered
- [ ] **Backward Compatibility**: Changes maintain backward compatibility

## Security Scanning
- [ ] **SAST**: Static Application Security Testing has passed
- [ ] **Secret Scanning**: No secrets are exposed in the code
- [ ] **Dependency Scanning**: No vulnerable dependencies are introduced
- [ ] **Container Scanning**: Container images are secure (if applicable)

## Compliance
- [ ] **License Compliance**: All code complies with project licenses
- [ ] **Export Control**: No export-controlled technology is included
- [ ] **Privacy**: No personal data is processed or stored
- [ ] **Regulatory**: Changes comply with applicable regulations

## Deployment
- [ ] **Breaking Changes**: Breaking changes are documented
- [ ] **Migration**: Migration procedures are documented (if needed)
- [ ] **Rollback**: Rollback procedures are documented (if needed)
- [ ] **Monitoring**: Monitoring and alerting are updated (if needed)

## Description
<!-- Provide a clear description of the changes in this PR -->

## Security Impact
<!-- Describe any security implications of these changes -->

## Testing
<!-- Describe how these changes have been tested -->

## Additional Notes
<!-- Any additional information that reviewers should know -->

---

**Security Review**: [ ] Approved [ ] Requires Changes [ ] Rejected
**Reviewer**: ________________
**Date**: ________________
