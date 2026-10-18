# Backend stderr redaction

mcp-flow redacts a stdio backend's stderr on two paths:

- **Live passthrough** (the gateway's own stderr): redacted line by line as it streams, with
  private key armor state carried across lines (PEM, PGP, SSH2, OpenVPN, PuTTY .ppk).
- **Init-error tail** (the thrown startup error, the tool result built from it, and the
  audit_events row that records that result): a second line redactor feeds a bounded buffer
  (12000 characters kept; memory about 24000 characters, which one write can briefly exceed by
  up to about 64 KiB). When a backend fails to start, that buffer
  is redacted again as a whole and cut to 8000 characters. Only redacted text is ever cut.

## Fail-closed rules

- A key block whose BEGIN line was seen is redacted up to its END. On the init-error tail an
  unclosed block is redacted to the end of the stream. On live stderr it is redacted for 1024
  lines, then key-body-shaped lines (base64 of 16+ characters, armor headers, `=XXXX`
  checksums) stay redacted until the first other line.
- A stray END marker whose BEGIN never appeared: the run of key-body-shaped lines right before
  it is redacted. On the init-error tail the END marker is kept for the second pass, so those
  lines are redacted there too. This also holds when the stray END is followed by a new BEGIN on the same line
  (`-----END … KEY----------BEGIN … KEY-----`); the new block is then redacted as usual.

## Known limit: live stderr cannot take back printed lines

Live passthrough writes each line as soon as it is complete. If a backend prints key-body lines
**without** the BEGIN line and an END marker only arrives afterwards, those body lines have
already been written to the gateway's stderr; only the END line itself is redacted. The
init-error tail, the tool result and audit_events are not affected (the second pass redacts
the run). Keep backend stderr out of shared log sinks if a backend may print key material.
