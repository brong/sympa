# DKIM2 Message-Instance Support for Sympa

This document describes the changes made to add DKIM2 Message-Instance
header support to Sympa, their impact on resource usage, and their
effect on generated emails.

## Overview

DKIM2 (draft-clayton-dkim2-spec-08) provides verifiable chain of custody
for email messages.  Each intermediary that modifies a message documents
its changes by adding a Message-Instance header containing cryptographic
hashes and diff recipes.  Downstream verifiers can use these to
reconstruct earlier versions of the message and verify each hop's
hashes.

Sympa, as a mailing list manager, modifies messages by adding headers
(List-Id, Reply-To, etc.), appending footers, personalizing content,
and re-encoding bodies.  These changes must be captured in
Message-Instance headers so downstream recipients can verify the
original message.

## How Message-Instance recipes work

The MI v=2 header contains recipes that allow reconstructing the
**previous** (original) message from the **current** (modified) message.
Recipe entries are:

- `[start, end]`: copy a range of lines from the **current** body
  (1-based, inclusive)
- `"text"`: emit a literal line from the **previous** body

This means:

| Modification | Recipe |
|---|---|
| Footer appended (lines match) | Single `[1, N]` copy range — footer lines are simply unreferenced and dropped during undo |
| Footer appended, last base64 line changed due to padding shift | `[1, N-1]` copy range + 1 literal for the original last line |
| Inline substitution (personalization) | Copy ranges around the edit + literals for the original text at the edit point |
| Full re-encoding (no lines match) | All literals — entire original body stored in recipe |

The goal of the encoding-preservation commits below is to keep
modifications in the "lines match" category wherever possible, so
recipes stay compact (a single copy range for the unchanged body).

## Changes

### Skip re-encoding when personalization makes no changes

**File:** `src/lib/Sympa/Message.pm` (`_merge_msg`)

In `_merge_msg()`, saves the UTF-8 body before calling
`personalize_text()`, then compares after.  If identical (no template
variables were substituted), returns the entity immediately without
calling `body_encode()`.

**Why:** `body_encode()` decodes from the original charset, then
re-encodes.  For base64 content, this can produce different line
wrapping.  For quoted-printable, different soft break placement.  The
round-trip is not guaranteed to be byte-identical even when nothing
semantic changed.

**Impact on generated emails:** Messages where personalization is
enabled but no template variables appear in a particular MIME part
will now preserve the original body bytes exactly.  Previously these
parts might get subtly re-encoded (different base64 line wrapping,
etc.).  The semantic content is identical either way.

**Memory:** One extra string copy of the UTF-8 body per text part,
freed immediately on return.  Negligible.

**CPU:** One string comparison (`eq`) per text part.  This is cheaper
than the `body_encode()` call it skips, so this is a net CPU savings
for the common case.  Slight overhead (the comparison) when
substitution does happen.

**Disk:** None.

### Prefer original charset when re-encoding

**Files:** `src/lib/Sympa/Message.pm` (`_merge_msg`,
`_append_footer_header_to_part`)

Before calling `body_encode()` with `Replacement => 'FALLBACK'`
(which allows charset change to UTF-8), first tries `body_encode()`
without the FALLBACK flag.  If the content fits in the original
charset, uses that result.  Only falls back to UTF-8 if the first
attempt fails or produces a different charset.

**Why:** Previously, `body_encode($text, Replacement => 'FALLBACK')`
could change charset to UTF-8 based on MIME::Charset heuristics.
Even if all the added content was pure ASCII (like a URL in a footer),
the fallback mechanism could trigger a charset change, which also
changes Content-Transfer-Encoding and rewrites the entire body on
the wire.

**Impact on generated emails:**

- Common case (footer/personalization content fits in original
  charset): No change to output.  The body stays in its original
  charset and CTE.
- Rare case (content can't be represented in original charset): Same
  as before -- falls back to UTF-8 with FALLBACK.

**Memory:** One extra scalar for `$decoded_utf8`.  Negligible.

**CPU:** One extra `body_encode()` call in the worst case (original
charset fails, then retry with FALLBACK).  In the common case, same
cost as before.

**Disk:** None.

### Fall back to MIME parts when inline footer append fails

**File:** `src/lib/Sympa/Message.pm` (`decorate`)

When `footer_type` is `append` and `_append_parts()` returns undef
(failure), instead of silently dropping the footer, falls back to
`_add_footer_part()` which adds header/footer/global_footer as
separate MIME parts.

**Why:** `_append_parts()` can fail when the body encoding is
non-standard, the body can't be decoded, or the combined content
can't be represented in the original charset.  Previously the footer
was silently lost.

**Impact on generated emails:**

- Messages where `_append_parts()` already succeeds: Zero change.
- Messages where `_append_parts()` was failing silently: These will
  now get footers they previously did not.  The message structure
  changes from single-part to `multipart/mixed` (original body as
  first part, footer as second part).  This is a visible change --
  recipients will see footers they were not seeing before.  Some MUAs
  may render the multipart structure slightly differently.
- Only affects lists with `footer_type = append`.  Lists using
  `footer_type = mime` already used `_add_footer_part()`.

**Memory:** In the fallback path, creates additional MIME::Entity
objects for footer parts.  Same cost as `mime` mode.  Only triggered
on failure of the inline path (uncommon).

**CPU:** In the fallback path, same cost as `mime` mode.

**Disk:** None.

### DKIM2 Message-Instance support at ingress and egress

**Files:** `src/lib/Sympa/Message.pm`,
`src/lib/Sympa/Spindle/ProcessIncoming.pm`,
`src/lib/Sympa/Spindle/ProcessOutgoing.pm`,
`src/lib/Sympa/Spool/Outgoing.pm`

**Soft dependency:** All MI functionality requires
`Mail::DKIM2::MessageInstance` (from the DKIM2 interop library).  If
not installed, MI headers are not added and no `.mi_orig` files are
written.  No errors occur.  The feature is completely invisible when
the dependency is absent.

#### Ingress (ProcessIncoming)

Before any content modifications, if no Message-Instance header is
present, calculates MI v=1 capturing SHA-256 hashes of the original
message headers and body.  Stores the original message (with MI v=1
header added) as `$message->{mi_original}` for later diffing.

Messages arriving with existing MI headers (from upstream hops) are
left alone -- no duplicate v=1 is added.

`as_rfc822_string()` normalizes line endings to CRLF for wire-format
compatibility with DKIM body canonicalization.

#### Spool persistence (Spool::Outgoing)

The original message is persisted as a `.mi_orig` file alongside the
message file in the outgoing spool (`queuebulk/msg/`).  This bridges
the process boundary between `sympa_msg.pl` (ingress) and `bulk.pl`
(egress).

When multiple spool entries exist for the same message (VERP and
non-VERP batches, different reception modes), the `.mi_orig` files
are hard linked to avoid data duplication.  The `orig_msg` option
passed through `store()` allows `_mail_message()` to record the
first `.mi_orig` path on the message object, so subsequent calls
hard link to it.

Cleanup: `.mi_orig` files (or hard links) are removed in `remove()`
and `quarantine()` alongside the message file.

#### Egress (ProcessOutgoing)

After all content transformations (personalization, decoration,
S/MIME) but before DKIM signing:

- **Relayed messages** (have `mi_original`): Compares header and body
  hashes of the current message against the original.  If unchanged,
  skips MI v=2 entirely.  If changed, calculates MI v=2 with diff
  recipes.
- **Internally generated messages** (notifications, digests, etc.):
  Adds MI v=1 as originator since Sympa authored the message.

#### Resent archive messages (ResendArchive)

Messages resent from the archive bypass ProcessIncoming.  If the
archived message has MI headers (archived after DKIM2 support was
added), sets `mi_original` from the archived state.  If no MI
headers exist (pre-DKIM2 archive), adds MI v=1 capturing the
archived content as baseline.

#### Direct-send messages (ToMailer)

Messages sent directly via the mailer spindle (bypassing the bulk
spool) get MI v=1 before delivery if no MI headers are present.

### Quoted-printable preservation in decoration

**File:** `src/lib/Sympa/Message.pm` (`_append_footer_header_to_part`)

When appending footers to quoted-printable text/plain messages,
concatenates at the raw QP-encoded level rather than decoding,
concatenating, and re-encoding.  Only the footer text is freshly
QP-encoded; the original body lines remain byte-identical.

**Why:** The standard decode-concatenate-reencode path destroys the
sender's QP choices (unnecessarily-quoted characters like `=48` for
`H`, non-standard soft line break positions).  Re-encoding changes
every line, producing a body recipe that stores the entire original
body as literals.  Raw QP concatenation preserves the sender's
encoding, so the MI body recipe is a single `[1, N]` copy range.

Falls back to the standard path if the footer text cannot be encoded
in the message's charset.

### Base64 line wrapping preservation

**File:** `src/lib/Sympa/Message.pm` (`set_entity`,
`_restore_b64_wrapping`)

When MIME::Entity re-encodes a base64 body after modification, it
uses standard 76-char line wrapping.  If the sender used a different
line length, every base64 line changes on the wire.

For single-part base64 messages, `set_entity()` restores the original
line wrapping by diffing the flat (whitespace-stripped) base64 strings
using Algorithm::Diff and reconstructing the output with original
line breaks for unchanged character blocks.

**Why:** Without this, the MI body recipe must store the entire
original body as literals (every line changed).  With restored
wrapping, the recipe is a compact copy range for unchanged lines
plus a single literal for the last changed line (where base64
padding shifted due to the appended content).

Only applies to single-part messages.  For multipart messages, the
`Mail::DKIM2::MessageInstance` library's byte-level prefix/suffix
matching strategy handles the case where line wrapping cannot be
preserved.

## Message path coverage

| Message path | MI treatment |
|---|---|
| List distribution (ToList) | v=1 at ingress, v=2 at egress with recipes |
| Forward to -owner/-editor (DoForward) | v=1 at ingress (inherits ProcessIncoming), v=2 at egress |
| Resent from archive (ResendArchive) | v=1 from archive or added fresh, v=2 at egress |
| Template notifications (send_file, send_dsn) | v=1 at egress (Sympa as originator) |
| Digest messages (ProcessDigest) | v=1 at egress (Sympa as originator) |
| Direct-send messages (ToMailer) | v=1 before delivery |

## Resource impact

### Generated email size

MI headers add approximately 150-300 bytes per message when nothing
changed (v=1 only, or v=2 with hashes but the skip-if-unchanged
optimisation fires), or 300-600 bytes when body/header recipes are
present.  Recipes are compact when encoding is preserved:

- Footer append with lines matching: recipe is a single `[1, N]`
  copy range (the footer is simply not referenced)
- Footer append with base64 padding shift: `[1, N-1]` range + 1
  literal for the changed last line
- Inline personalization: copy ranges around edit points + literals
  for original text
- Full re-encoding (worst case): entire original body as literals

### Memory

| Operation | Extra memory | Lifetime |
|-----------|-------------|----------|
| `as_rfc822_string()` at ingress | 1x message size | Freed after MI calculation |
| `mi_original` on Message object | 1x message size | Until spool write completes |
| `.mi_orig` loaded in ProcessOutgoing | 1x message size | Duration of `__twist_one` |
| Hash comparison at egress | 2x Email::MIME objects | Freed if hashes match (skip path) |
| Full `calculate()` at egress | 2x Email::MIME + Algorithm::Diff | Duration of `calculate()` |

Peak additional memory during egress MI calculation: approximately
4x message size.  For a 100KB message, approximately 400KB extra.
When the message is unchanged (skip path), only 2x message size for
the hash comparison.

### CPU

| Operation | Cost | Frequency |
|-----------|------|-----------|
| SHA-256 hashes at ingress | Proportional to message size | Once per message |
| SHA-256 hash comparison at egress | Proportional to message size | Once per recipient/batch |
| Full recipe computation (if changed) | O(n+d) typical | Once per recipient/batch |
| `Email::MIME->new()` parsing | Proportional to message size | 2x per recipient/batch |

The skip-if-unchanged optimisation avoids the expensive Algorithm::Diff
and recipe computation for messages that pass through without body or
header modifications.

### Disk

| Item | Size | Lifetime |
|------|------|----------|
| `.mi_orig` file per message | 1x message size | From spool write until all packets delivered |

Multiple spool entries for the same message share a single `.mi_orig`
file via hard links, so disk usage is 1x message size regardless of
how many batches (VERP, non-VERP, reception modes) are created.

For a busy list with 1000 queued messages averaging 50KB each, the
extra disk usage is approximately 50MB.  Files are cleaned up when
the message is fully delivered or quarantined.

### Orphaned files

If bulk.pl crashes or spool files are manually deleted, `.mi_orig`
files could be orphaned.  These are harmless and occupy the same
space as the (now-missing) message file.  They can be cleaned up by
removing any `.mi_orig` file in `queuebulk/msg/` that has no
corresponding message file (same name without the `.mi_orig` suffix).
