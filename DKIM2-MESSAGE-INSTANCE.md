# DKIM2 Message-Instance support for Sympa

Sympa changes the messages it redistributes: it adds list headers, a
subject tag, a header and footer, and sometimes rewrites the body. A DKIM2
verifier downstream can check the signatures of earlier hops only if every
hop that changed the message says what it changed. This change makes Sympa
do that: on lists that turn it on, each copy Sympa sends carries a
`Message-Instance` header field describing the copy, with a Recipe that
rebuilds the message as Sympa received it.

Sympa adds only `Message-Instance`. The `DKIM2-Signature` is added by the
MTA's outbound signer after Sympa hands the message over.

The wire format is the one in draft-ietf-dkim-dkim2-spec-06: `m=` numbers
the instance, `h=` carries `alg:header-hash:body-hash`, and `r=` the base64
JSON Recipe (`"h"` for the header fields, `"b"` for the body).

## The switch

A list parameter, `dkim2_message_instance` (`on`/`off`, group `dkim`),
which can also be set as a robot or site default. The default is `off`.

With it off Sympa behaves exactly as stock 6.2.78: no pseudo-header in the
spools, no MIME wrap, no `Message-Instance`. Turn it on per list:

```
dkim2_message_instance on
```

If the switch is on but Mail::DKIM2 0.15 or later cannot be loaded, Sympa
logs at `err` (once per process) and treats the list as off.

## Dependency

Mail::DKIM2 0.15 or later (`Mail::DKIM2::MessageInstance` and
`Mail::DKIM2::Common`): `cpanm Mail::DKIM2` once 0.15 is on CPAN; until
then install it from `perl/` in the DKIM2 interop repository
(<https://github.com/dkim2wg/interop>). 0.15 adds the `BodyRecipe` option
that lets the caller give the body Recipe instead of having it computed by
diff, and the `BodyHash` option that lets it give the body hash, so the
instance is calculated from the header block alone. Mail::DKIM2 is loaded
on first use, not at compile time, so Sympa without it runs as stock; an
older version counts as missing. In `cpanfile` it is the optional feature
`dkim2`.

## Ingress: before decryption, into a pseudo-header

`Spindle::ProcessIncoming` calls `Sympa::DKIM2::ingress` once per message,
after the S/MIME signature check and before `smime_decrypt` or any other
change.

1. If the message carries no `Message-Instance`, Sympa adds `m=1`
   describing it as received. If it carries one (added by an inbound milter
   or a signing sender), that one is kept: it already describes the message
   as received.
2. The header block as received (with the instance) is kept on the message
   object and serialised, base64, as the pseudo-header
   `X-Sympa-DKIM2-Headers`. `Sympa::Message::to_string` writes it and
   `new` reads it back, so it travels through every spool the message passes
   through (msg, moderation, held, auth, topic, bulk, bad) with no
   spool-specific code. It is not part of the message proper: `as_string`
   does not emit it, the archive stores the message without it, and the
   copy handed to a custom archiver has it removed.

The body is not saved: its hash is already in the top instance's `h=`.

Saving before decryption matters for S/MIME lists: the saved block, and so
every header Recipe built from it, describes the encrypted message as
received. No plaintext ever reaches a header field.

Anonymous lists skip ingress entirely: nothing about the original sender is
kept (see the table below).

## Decoration: always-wrap

On a DKIM2 list whose message has the saved header block, `decorate()`
does not edit the body. `Sympa::DKIM2::wrap` builds a new body instead:

```
Content-Type: multipart/mixed; boundary="=_dkim2_..."     (top level)

This is a multi-part message in MIME format.

--=_dkim2_...
<message_header part>                    (if the list has one)

--=_dkim2_...
<the message's Content-* fields, verbatim and in order>

<the original body, byte for byte>
--=_dkim2_...
<message_footer part>                    (if the list has one)

--=_dkim2_...
<global footer part>                     (if the robot has one)

--=_dkim2_...--
```

- The top-level `Content-*` fields move to the original part unchanged
  (`Content-Length` is dropped). The top level gets `MIME-Version`,
  `Content-Type: multipart/mixed`, and a `Content-Transfer-Encoding` of
  `8bit` or `binary` when the original or a decoration part needs it.
- The body is never parsed or re-encoded, so the original part's lines are
  the received body's lines, and the body Recipe is one copy range.
- The boundary is random and checked not to occur in the body or in any
  decoration part.
- The decoration parts are chosen and personalised as stock `decorate()`
  would: with `footer_type mime`, an existing `message_<kind>.mime` file is
  used as a MIME part (an empty one adds nothing, as stock); otherwise the
  text file becomes a `text/plain; charset=UTF-8` part. `footer_type
  append` therefore also wraps on a DKIM2 list: there is no inline append.
- Personalised footers are built per recipient; only the trailing part
  differs between copies.
- `multipart/signed`, `multipart/encrypted` and opaque
  `application/pkcs7-mime` (and `application/x-pkcs7-mime`) are left alone:
  wrapping them would break the signature or the encryption.
- Wrapping is all-or-nothing. The new header and body are built on copies
  and installed only at the end, so a failure leaves the message as it was.
  `decorate()` then logs at `err`, decorates the stock way, and marks the
  body as rewritten so egress gives it a null body Recipe.

`wrap` records the 1-based lines of the original body inside the new body
(none when the original body is empty); egress uses them as the copy range.

## Egress: one instance per copy

`Spindle::ProcessOutgoing` calls `Sympa::DKIM2::egress_context` once per
packet, before any per-recipient change, then `Sympa::DKIM2::egress_add`
in `__twist_one` for each copy, after every transformation and before DKIM
and ARC signing.

`egress_context`:

1. With no saved header block (a message Sympa composed itself, a digest,
   or a message queued before the switch was turned on), add nothing. Log
   at `info` if the message carries a `Message-Instance` or
   `DKIM2-Signature` (a relayed post that missed ingress), else at `debug`.
2. Check the saved block's top instance header hash against the saved
   block itself. On a mismatch, log at `err` and add nothing: Sympa never
   builds on a broken chain.
3. Hash the current body and compare it with the top instance's body hash.
   Equal means nothing has rewritten the body since ingress.

`egress_add`:

1. Remove `Bcc` and `Resent-Bcc`, so their removal is in the header Recipe.
2. Choose the body Recipe:

   | Body | Body Recipe |
   |---|---|
   | changed before the packet (txt, html, urlize, notice modes, content filters, anything else), or rewritten for this copy (full-body merge, `smime_sign`, `smime_encrypt`, stock fallback after a failed wrap) | null (`"b": null`) |
   | wrapped | one copy range of the original lines (`[]` for an empty original body) |
   | not decorated | none: the body is unchanged |

3. Self-check: a copy range or "none" is used only if applying it to the
   outgoing body gives back a body whose hash is the top instance's body
   hash, counting lines as the verifier does. Otherwise something changed
   the body without saying so; Sympa logs at `notice` and uses a null body
   Recipe. For a copy range the check usually costs no hash: the copied
   lines are compared byte for byte with the packet's body, which
   `egress_context` hashed. Only when they differ (the lines were rewritten,
   or their line ends changed) are they hashed.
4. Compute the instance with `Mail::DKIM2::MessageInstance->calculate`,
   diffing the saved header block against the outgoing header block for the
   header Recipe. The outgoing body is hashed once, here, and passed in
   (`BodyHash`), so `calculate` sees the header block only: the body is
   never parsed as MIME, nor the copy built as one string. If nothing
   changed at all (no header change, body Recipe "none"), no instance is
   added.
5. Add it as the next `m=` (one more than the highest present) at the top of
   the header, folded with Mail::DKIM2's folder.

The whole step runs in an `eval`. On any failure it logs and the copy goes
out without the new instance: DKIM2 never blocks or loses list mail.

The instance is computed for every copy, one body hash and one header diff
each, also when the copies differ only in the envelope (VERP, DSN
tracking) and could share one instance. Reusing it would mean telling such
copies apart from personalised ones; computing it per copy is simpler, and
the measured cost is small (see "Resource impact").

### The null body Recipe

A null body Recipe says "the previous body cannot be rebuilt". A verifier
can still check the previous hop's header hash, because the header Recipe
rebuilds the previous header block, but it cannot check the earlier body
hashes. Sympa uses it whenever the outgoing body is neither the received
body nor the received body wrapped, because the alternative is a Recipe
carrying the whole original body (a 300 KB attachment gave a 572 KB header
in the old series).
The test is always against the body hash in the top instance's `h=`, so a
body change Sympa did not anticipate still gives a correct, if null,
Recipe rather than a wrong one.

An outbound `dkim2-milter` refuses to sign a message whose top instance
has a null body Recipe unless it is started with `--allow-null-body-recipe`.
A list host running Sympa needs that option on its outbound signer.

### Ordering

Nothing that changes a hashed header field may run after `egress_add`.
On a DKIM2 list (when `egress_context` returned a context) the envelope and
tracking block, which sets `Disposition-Notification-To` for MDN tracking,
runs before the DKIM2 step; on every other list it stays where stock Sympa
has it, after DKIM and ARC signing. DomainKey-Signature removal already
comes before the DKIM2 step.

## Special cases

| Case | Behaviour |
|---|---|
| S/MIME encrypted list | header block saved before decryption; the re-encrypted body differs, so null body Recipe; no plaintext in any header field |
| `multipart/signed`, `multipart/encrypted`, opaque `application/pkcs7-mime` | not wrapped; body Recipe none (or null if the copy is S/MIME signed or encrypted) |
| txt, html, urlize, notice reception modes | null body Recipe, small header Recipe |
| Full-body personalisation (`personalization.mail_apply_on all`) | null body Recipe per recipient |
| Footer-only personalisation (`personalization.mail_apply_on footer`) | wrap; the copies differ only in the trailing part |
| Anonymous list | no pseudo-header at ingress, stock decoration; egress removes `DKIM2-Signature` and `Message-Instance`, and the outbound signer starts a new chain with `m=1` |
| Resend from archive | on a DKIM2 list, the chain is removed as for anonymous lists |
| Digests, notifications, auto-replies, direct sends, bounces | no saved header block; Sympa adds nothing (the outbound signer adds `m=1`) |
| Messages embedded in a digest | content, left alone |
| VERP, DSN tracking | envelope only; the instance is still computed per copy (below) |
| MDN tracking | `Disposition-Notification-To` is set before the DKIM2 step |
| DMARC From rewrite, subject tag, custom headers, topics, `remove_headers` | header changes, captured by the header diff at egress |
| Moderated, held, auth-confirmed messages | the pseudo-header is in the spooled text, so the chain survives |
| Requeued from `bad/` | likewise; ingress keeps the saved header block it finds |
| Archive and custom archiver copies | stored without the pseudo-header |

### `remove_headers`

Fields removed by `remove_headers` that are covered by the header hash (not
`X-` fields, not trace fields) are recorded in the header Recipe, as spec
§5.1 requires: the Recipe must rebuild the previous header block. So a
field removed for privacy is still readable, in the Recipe, by anyone who
receives the copy. Remove such fields before the message reaches a
DKIM2-signing hop, or leave the list off.

## Resource impact

With the switch off, nothing new runs beyond one parameter lookup per
message, and the output is byte-identical to stock (`util/off-identical.sh`).

With it on, per copy: one body hash, a header diff and a self-check
(normally a byte compare); the header block is parsed, never the body.
Per packet: one body hash in `egress_context`, and `orig_body`, the
body as it was at ingress, kept as a second copy of the packet's body for
the self-check. Spool: the saved header block is a pseudo-header of a few
KB, and there is no extra spool file (the old series kept a `.mi_orig`
copy of the whole message).

Measured against stock 6.2.78 on a small host (2 vCPU, 2 GB, in-process,
DKIM2-signed input, 25 members, footer and personalised footer):

- CPU: 0.8x to 1.3x of stock for messages up to 100 KB (QP text much
  faster, probably because stock re-encodes it), 1.2x to 1.8x for the 1 MB
  and 10 MB attachments. A personalised footer on a 10 MB attachment takes
  5.1 s against 3.3 s.
- Memory: within about 1 MB of stock up to 100 KB, below stock for the 1 MB
  and 10 MB attachments (the 10 MB case peaks at +214 MB against +274 MB).
- Wire: the `Message-Instance` header is 366 to 476 bytes whatever the
  message; larger messages grow by well under 1% per copy.

The old CTE-preserving series, by comparison, took 14 to 41 times stock CPU
on Outlook-style HTML and QP text (with personalisation: 25 per-recipient
copies), timed out on a base64 attachment wrapped at 72 columns, ran out of
memory at 10 MB, and wrote a 134 KB header for a 100 KB QP message. The
figures, method and limits are in `docs/sympa-dkim2-performance.md` of the
DKIM2 interop repository.

## Tests

`t/DKIM2.t`, in `check_SCRIPTS`. It needs Mail::DKIM2 on `PERL5LIB`
(CPAN, or `perl/lib` of the DKIM2 interop repository) and fails rather than
skipping without it:

```
PERL5LIB=/path/to/Mail-DKIM2/lib prove -Isrc/lib t/DKIM2.t
```

It drives the real `decorate()`, `ingress`, the spool round trip and
`ProcessOutgoing`, and checks the output with Mail::DKIM2's verifier and
undo.
