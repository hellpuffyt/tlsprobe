# Security policy

## Supported versions

Only the latest release on the default branch receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability.
Report it privately through GitHub's advisory form:

https://github.com/hellpuffyt/tlsprobe/security/advisories/new

Include the version or commit, a description of the issue, and steps or
input that reproduce it. You should receive an acknowledgement within a
few days; once a fix is available it will be released and credited in
the advisory unless you prefer otherwise.

## Scope

tlsprobe connects to servers and parses the certificates they present, so that input is untrusted. Relevant reports include crashes or hangs triggered by a server, a chain reported as trusted when browsers would reject it, and missed findings that hide a real weakness. tlsprobe deliberately completes handshakes with invalid certificates; that is by design and not a vulnerability.
