# Application Security Documentation

## Overview

This document describes the security features implemented in this ASP.NET Core application to protect against common web vulnerabilities as defined by OWASP.

---

## HTTP Status Codes Reference

| Code | Name | Description |
|------|------|-------------|
| 200 | OK | Request succeeded |
| 201 | Created | Resource created successfully |
| 204 | No Content | Request succeeded, no content returned |
| 301 | Moved Permanently | Resource moved to new URL permanently |
| 302 | Found | Resource temporarily at different URL |
| 400 | Bad Request | Server cannot process request due to client error |
| 401 | Unauthorized | Authentication required but not provided/invalid |
| 403 | Forbidden | Server refuses to authorize the request |
| 404 | Not Found | Requested resource not found |
| 405 | Method Not Allowed | HTTP method not supported for this resource |
| 408 | Request Timeout | Server timed out waiting for request |
| 429 | Too Many Requests | Rate limiting - too many requests |
| 500 | Internal Server Error | Unexpected server error |
| 501 | Not Implemented | Server doesn't support required functionality |
| 502 | Bad Gateway | Invalid response from upstream server |
| 503 | Service Unavailable | Server temporarily unable to handle request |

---

## Security Features Implemented

### 1. Cross-Site Scripting (XSS) Protection

**Implementation:**
- Content-Security-Policy (CSP) header restricts script sources
- X-XSS-Protection header enables browser XSS filter
- All user input is HTML-encoded before display
- InputSanitizationService detects XSS patterns

**Files:**
- `Middleware/SecurityHeadersMiddleware.cs`
- `Services/InputSanitizationService.cs`

**CSP Directive:**
```
default-src 'self';
script-src 'self' 'unsafe-inline' https://www.google.com;
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
frame-ancestors 'none';
```

### 2. SQL Injection Prevention

**Implementation:**
- Entity Framework Core with parameterized queries
- InputSanitizationService detects SQL injection patterns
- Special characters in login fields trigger security response
- No raw SQL queries - all ORM-based

**Detected Patterns:**
- Single quotes (')
- SQL keywords (SELECT, INSERT, UPDATE, DELETE, DROP)
- Comment sequences (--, /*, */)
- OR/AND equality patterns

### 3. Sensitive Data Protection

**Implementation:**
- NRIC encrypted with AES-256 before storage
- Passwords hashed with Argon2id (memory-hard algorithm)
- Session tokens securely generated
- No sensitive data in URLs or logs

**Files:**
- `Services/EncryptionService.cs` - AES-256 encryption
- `Services/PasswordService.cs` - Argon2id hashing

### 4. Security Misconfiguration Prevention

**Implementation:**
- Custom error pages hide server details
- No exposed metrics endpoints
- Server version headers removed
- Dangerous file extensions blocked
- Hidden directories protected

**Files:**
- `web.config` - IIS security settings
- `Views/Error/*.cshtml` - Custom error pages

### 5. Clickjacking Protection

**Implementation:**
- X-Frame-Options: DENY
- frame-ancestors 'none' in CSP

### 6. CSRF Protection

**Implementation:**
- Anti-forgery tokens on all POST forms
- SameSite=Strict cookie policy
- X-CSRF-TOKEN header support

### 7. Session Security

**Implementation:**
- HttpOnly cookies (no JavaScript access)
- Secure cookies (HTTPS only in production)
- SameSite=Strict (no cross-site requests)
- Session token validation against database
- Automatic session timeout

---

## Custom Error Pages

All error pages use `_ErrorLayout.cshtml` which:
- Does not expose server technology
- Does not show stack traces
- Provides user-friendly messages
- Logs errors for administrators

| Error | View | Description |
|-------|------|-------------|
| 400 | 400.cshtml | Bad Request |
| 401 | 401.cshtml | Unauthorized |
| 403 | 403.cshtml | Forbidden |
| 404 | 404.cshtml | Not Found |
| 405 | 405.cshtml | Method Not Allowed |
| 429 | 429.cshtml | Too Many Requests |
| 500 | 500.cshtml | Server Error |
| 503 | 503.cshtml | Service Unavailable |

---

## Exception Handling

### Global Exception Handler

The `ExceptionHandlingMiddleware` catches all unhandled exceptions and:
1. Logs full exception details (for developers)
2. Returns appropriate HTTP status code
3. Redirects to custom error page
4. Never exposes stack traces to users

```csharp
// Example: DivideByZeroException
try
{
    var result = 10 / 0;
}
catch (Exception ex)
{
    // Logged for developers
    // User sees friendly 500 error page
}
```

### Try-Catch Best Practices

All database operations and external calls are wrapped in try-catch:
- Specific exceptions caught first
- Generic exceptions logged
- User-friendly messages displayed

---

## IIS Security Configuration (web.config)

### Headers Removed
- X-Powered-By
- Server

### Headers Added
- X-XSS-Protection: 1; mode=block
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: strict-origin-when-cross-origin

### Blocked URL Sequences
- `..` (path traversal)
- `.git`, `.svn`, `.env` (sensitive files)
- `web.config` (configuration)

### Blocked File Extensions
- `.cs` (source code)
- `.config` (configuration)
- `.dll` (binaries)
- `.sql`, `.mdf`, `.ldf` (database)
- `.log`, `.bak` (logs/backups)

### Blocked HTTP Verbs
- TRACE
- TRACK
- DEBUG
- OPTIONS

---

## Database Security

### Password Storage
- Algorithm: Argon2id
- Salt: Unique per password
- Parameters: Memory=65536KB, Iterations=4, Parallelism=8

### Sensitive Field Encryption
- Algorithm: AES-256-CBC
- Fields: NRIC
- Key: Stored in configuration (should use Key Vault in production)

### Password Policy
- Minimum length: 12 characters
- Required: Uppercase, lowercase, number, special character
- History: Last 2 passwords cannot be reused
- Maximum age: 90 days
- Minimum age: 1 minute

---

## Authentication Security

### Two-Factor Authentication
- Method: Email OTP
- Code length: 6 digits
- Expiry: 5 minutes

### Account Lockout
- Threshold: 3 failed attempts
- Duration: 15 minutes
- Auto-unlock: Yes

### Session Management
- Timeout: 30 minutes
- Token validation: Per-request
- Single session: New login invalidates old session

---

## Audit Logging

All security events are logged:
- Login attempts (success/failure)
- Password changes
- Account lockouts
- 2FA verification
- Profile updates

Log fields:
- UserId
- Action
- Timestamp
- IP Address
- Details

---

## Testing with OWASP ZAP

### XSS Testing
1. Try `<script>alert('XSS')</script>` in input fields
2. Try `<iframe src="javascript:alert('XSS')">` in "Who Am I"
3. Verify CSP blocks inline scripts

### SQL Injection Testing
1. Try `' OR '1'='1` in email field
2. Try `'; DROP TABLE Members; --` in password
3. Verify generic error message (no SQL details)

### Sensitive Data Exposure Testing
1. Try accessing `/ftp`, `/admin`, `/metrics`
2. Verify 404 error (not directory listing)
3. Check response headers for version info

### Security Misconfiguration Testing
1. Try double-encoding in URLs
2. Try accessing `.git`, `.env` files
3. Verify blocked by web.config rules

---

## Security Checklist

- [x] Input validation on all user inputs
- [x] Output encoding for XSS prevention
- [x] Parameterized queries for SQL injection prevention
- [x] HTTPS enforced in production
- [x] Secure cookie settings
- [x] CSRF protection tokens
- [x] Custom error pages
- [x] Security headers configured
- [x] Password hashing with strong algorithm
- [x] Sensitive data encryption
- [x] Session security
- [x] Audit logging
- [x] Account lockout policy
- [x] Two-factor authentication
- [x] IIS hardening

---

## Files Reference

| File | Purpose |
|------|---------|
| `Middleware/SecurityHeadersMiddleware.cs` | Security HTTP headers |
| `Middleware/ExceptionHandlingMiddleware.cs` | Global exception handling |
| `Middleware/SessionValidationMiddleware.cs` | Session token validation |
| `Services/InputSanitizationService.cs` | Input validation |
| `Services/EncryptionService.cs` | AES-256 encryption |
| `Services/PasswordService.cs` | Argon2id hashing |
| `Services/AuditLogService.cs` | Security event logging |
| `web.config` | IIS security configuration |
| `Views/Error/*.cshtml` | Custom error pages |
| `Views/Shared/_ErrorLayout.cshtml` | Error page layout |
