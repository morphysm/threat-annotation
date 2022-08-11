# famed-annotated report 11 Aug 22 17:42 CEST
## Diagram
## Exposures

### #xss against WebApp:App
insufficient input validation.
### content injection against WebApp:App
insufficient input validation.
## Mitigations

### unauthorised access against WebApp:FileSystem mitigated by #file_perms:

### resource access abuse against WebApp:Web mitigated by basic input validation.

### privilege escalation against WebApp:Web mitigated by non-privileged port

## Reviews

### WebApp:Web
Is this a security feature?
## Connections

### User:Browser To WebApp:Web
HTTP:8080


## Components

### #file_writes

### HTTP:8080

### WebApp:Web.

### arbitrary file reads

### #xss

### Is this a security feature?

### User:Browser

### WebApp:FileSystem

### WebApp:Web

### content injection

## Controls

### non-privileged port
non-privileged port
### #file_perms:
#file_perms:
### Web Application Firewall (#waf):
Web Application Firewall (#waf):
### basic input validation.
basic input validation.
## Threats

### unauthorised access
unauthorised access
### @cwe_319_cleartext_transmission
@cwe_319_cleartext_transmission
### Cross-site Scripting (#xss):
Cross-site Scripting (#xss):
### WebApp:FileSystem
WebApp:FileSystem
### arbitrary file writes (#file_writes):
arbitrary file writes (#file_writes):
### insufficient input validation.
insufficient input validation.
### privilege escalation
privilege escalation
### resource access abuse
resource access abuse