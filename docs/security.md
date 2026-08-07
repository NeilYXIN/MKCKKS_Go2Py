# Security and threat model

MKCKKS Go2Py is research software and has not been independently audited.
Neither the upstream presets nor this wrapper carry a new security-strength
claim.

The library performs local cryptographic computation. It is not an
authenticated network protocol and does not provide malicious-party security,
CCA security, a threshold policy, transport authentication, or side-channel
guarantees beyond the pinned upstream implementation.

Applications must authenticate parties and transport. Decryption shares and
private state are sensitive. Raw private exports are unencrypted. Go and Python
cannot guarantee complete memory zeroization; process inspection, swap, and
core dumps remain risks.

Artifact checksums detect accidental corruption only. Deserializing attacker-
controlled data remains subject to configured size limits and parser checks,
but applications must authenticate artifacts before use.

Report suspected vulnerabilities privately as described in the
[security policy](../SECURITY.md).
