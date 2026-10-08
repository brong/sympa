# -*- indent-tabs-mode: nil; -*-
# vim:ft=perl:et:sw=4

# Sympa - SYsteme de Multi-Postage Automatique
#
# Copyright (c) 1997, 1998, 1999 Institut Pasteur & Christophe Wolfhugel
# Copyright (c) 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
# 2006, 2007, 2008, 2009, 2010, 2011 Comite Reseau des Universites
# Copyright (c) 2011, 2012, 2013, 2014, 2015, 2016, 2017 GIP RENATER
# Copyright 2017, 2018, 2019, 2020, 2021, 2022 The Sympa Community. See the
# AUTHORS.md file at the top-level directory of this distribution and at
# <https://github.com/sympa-community/sympa.git>.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

package Sympa::DKIM2;

use strict;
use warnings;
use English qw(-no_match_vars);
use MIME::Parser;

use Sympa;
use Conf;
use Sympa::Log;

my $log = Sympa::Log->instance;

# True if $that is a list with dkim2_message_instance on and Mail::DKIM2
# 0.15 or later loadable.  Mail::DKIM2 is loaded on first use, never at
# compile time.  An older one lacks what egress needs, so it counts as
# missing.  The failure is logged once per process.
my $load_error_logged;

sub enabled {
    my $that = shift;
    return 0 unless ref $that eq 'Sympa::List';
    return 0
        unless ($that->{'admin'}{'dkim2_message_instance'} || 'off') eq 'on';
    return 1 if eval {
        require Mail::DKIM2::MessageInstance;
        require Mail::DKIM2::Common;
        Mail::DKIM2::MessageInstance->VERSION('0.15');
        1;
    };
    $log->syslog('err',
        'dkim2_message_instance is on for %s but Mail::DKIM2 0.15 or later cannot be loaded: %s',
        $that, $EVAL_ERROR)
        unless $load_error_logged++;
    return 0;
}

sub anonymous {
    my $list = shift;
    return ($list->{'admin'}{'anonymous_sender'} // '') ne '' ? 1 : 0;
}

# At ingress, before any change (including S/MIME decryption): describe the
# message as received with m=1 unless it already carries an instance, and
# keep the header block for egress.  Anonymous lists keep nothing: their
# chain is stripped at egress.
sub ingress {
    my $message = shift;
    my $list    = $message->{context};
    return unless enabled($list);
    return if anonymous($list);
    # Requeued (from bad/, say): ingress already ran on this message.
    return if defined $message->{'dkim2_headers'};

    eval {
        unless ($message->{_head}->count('Message-Instance')) {
            my $mi = Mail::DKIM2::MessageInstance->calculate(
                _header_block($message), undef,
                BodyHash => Mail::DKIM2::MessageInstance::body_digest_raw(
                    $message->{_body}));
            _prepend_instance($message, $mi);
        }
        $message->{'dkim2_headers'} = $message->{_head}->as_string;
        1;
    } or $log->syslog('err', 'DKIM2 ingress failed for %s: %s',
        $message, $EVAL_ERROR);
}

# Once per packet, before any per-recipient change.  Returns undef (add
# nothing), {strip => 1} (anonymous: remove the chain), or {prev => the
# saved header block (CRLF, ending in a blank line), unchanged => 1 if the
# body is still the one the top instance hashed, body_hash => that hash,
# orig_body => that body when unchanged}.
sub egress_context {
    my $message = shift;
    my $list    = $message->{context};
    return undef unless enabled($list);
    return {strip => 1}
        if anonymous($list) or $message->{shelved}{dkim2_strip};
    unless (defined $message->{'dkim2_headers'}) {
        # Worth an info line only for a post that carries a DKIM2 chain
        # (relayed, but it missed ingress); otherwise it is routine.
        my $relayed = grep { $message->{_head}->count($_) }
            qw(Message-Instance DKIM2-Signature);
        $log->syslog(($relayed ? 'info' : 'debug'),
            'DKIM2: %s has no saved header block; no Message-Instance added',
            $message);
        return undef;
    }
    my $ctx = eval {
        (my $prev = $message->{'dkim2_headers'} . "\n") =~ s/\r?\n/\r\n/g;
        my ($ok, $why) =
            Mail::DKIM2::MessageInstance->verify($prev, HeadersOnly => 1);
        die "saved header block does not verify: " . ($why // '') . "\n"
            unless $ok;
        my $top = _top_instance($prev);
        my $unchanged =
            Mail::DKIM2::MessageInstance::body_digest_raw($message->{_body})
            eq $top->body_hash;
        {   prev      => $prev,
            unchanged => ($unchanged ? 1 : 0),
            body_hash => $top->body_hash,
            ($unchanged ? (orig_body => $message->{_body} // '') : ())
        };
    };
    $log->syslog('err', 'DKIM2: %s: %s; no Message-Instance added',
        $message, $EVAL_ERROR)
        unless $ctx;
    return $ctx;
}

# The highest-numbered Message-Instance in a header block.
sub _top_instance {
    my $prev = shift;
    my @mi =
        Mail::DKIM2::Common::parse_mime($prev)->header_raw('Message-Instance');
    my ($top) = sort {
        Mail::DKIM2::Common::extract_mi_version($b)
            <=> Mail::DKIM2::Common::extract_mi_version($a)
    } @mi;
    return Mail::DKIM2::MessageInstance->parse($top);
}

# Last step before DKIM/ARC: describe this copy's changes since ingress.
# The body Recipe is null if the body was rewritten (by the caller's
# account, by decorate()'s stock fallback, or as seen by egress_context),
# the copy range recorded by wrap() if it wrapped, else none.  A copy
# range or none is used only if the body it gives back hashes to the top
# instance's body hash; otherwise something changed the body unannounced,
# and the Recipe is null.  Never dies.
#
# A copy's body is hashed once, and the instance calculated from the
# header block alone: nothing here parses the body or builds the whole
# message as a string.
sub egress_add {
    my ($message, $ctx, %opts) = @_;
    return unless $ctx;
    eval {
        if ($ctx->{strip}) {
            _strip_chain($message);
            return 1;
        }
        $message->delete_header($_) for qw(Bcc Resent-Bcc);
        my $br;
        if (   !$ctx->{unchanged}
            or $opts{body_rewritten}
            or $message->{_dkim2_body_rewritten}) {
            $br = 'null';
        } elsif (my $lines = $message->{_dkim2_body_lines}) {
            $br = @$lines ? [[@$lines]] : [];
        } else {
            $br = 'none';
        }
        # A reference: copying the body is what this avoids.
        my $body = defined $message->{_body} ? \$message->{_body} : \'';
        my $bh = Mail::DKIM2::MessageInstance::body_digest_raw($$body);
        if ((ref $br or $br ne 'null')
            and not(ref $br
                ? _recovers_body($$body, $br, $ctx)
                : $bh eq $ctx->{body_hash})) {
            $log->syslog('notice',
                'DKIM2: body of %s changed after ingress; null body Recipe',
                $message);
            $br = 'null';
        }
        my $mi = Mail::DKIM2::MessageInstance->calculate(
            _header_block($message), $ctx->{prev},
            BodyRecipe => $br, BodyHash => $bh);
        # Nothing changed at all: no instance (spec: r= needs "h" or "b").
        return 1
            if !ref $br
            and $br eq 'none'
            and !$mi->get_tag('rh')
            and !$mi->get_tag('rb');
        _prepend_instance($message, $mi);
        1;
    } or $log->syslog('err',
        'DKIM2: Message-Instance for %s failed: %s; sent without it',
        $message, $EVAL_ERROR);
}

# True if the copy Recipe $br ([] or [[first, last]], from wrap()) applied
# to the body $_[0] gives back a body with the top instance's hash,
# $ctx->{body_hash}.  The body is used in place, never copied.  Lines are
# counted as the verifier splits them (/\r?\n/, trailing empty lines
# dropped).  Copies of one packet differ only outside the copied lines, so
# the usual answer comes from comparing those bytes with the packet's body,
# which egress_context() hashed ($ctx->{orig_body}): a memory compare, not
# a hash.  Anything else (an LF body sent as CRLF, say) is hashed.
sub _recovers_body {
    my (undef, $br, $ctx) = @_;
    my $bref = \$_[0];
    my $hash = $ctx->{body_hash};
    my ($first, $last) = @{$br->[0] || []};
    return Mail::DKIM2::MessageInstance::body_digest_raw('') eq $hash
        unless defined $first;
    my ($start, $end) = _line_span($bref, $first, $last) or return 0;
    return 1
        if defined $ctx->{orig_body}
        and _same_bytes($bref, $start, $end, \$ctx->{orig_body});
    return Mail::DKIM2::MessageInstance::body_digest_raw(
        substr($$bref, $start, $end - $start)) eq $hash;
}

# The byte offsets (start, end) of lines $first .. $last of $$bref, end
# being after line $last's line break (if it has one); empty if line $last
# is not one of the verifier's lines.  Walks forward to $first and back
# from the end to $last, so for a wrapped body only the few header and
# footer lines are visited.
sub _line_span {
    my ($bref, $first, $last) = @_;
    my $len   = length $$bref;
    my $start = 0;
    for (2 .. $first) {
        my $nl = index($$bref, "\n", $start);
        return if $nl < 0;
        $start = $nl + 1;
    }
    my $total = ($$bref =~ tr/\n//);
    my $end;
    if ($last <= $total) {
        $end = $len;
        $end = rindex($$bref, "\n", $end - 1) for 0 .. $total - $last;
        $end++;
    } elsif ($last == $total + 1 and $len and substr($$bref, -1) ne "\n") {
        $end = $len;
    } else {
        return;
    }
    # split() drops trailing empty lines: line $last must be followed, or
    # be made, by something other than line breaks.
    my $line_start = $last == 1 ? 0 : rindex($$bref, "\n", $end - 2) + 1;
    pos($$bref) = $line_start;
    my $only_breaks = $$bref =~ /\G(?:\r?\n)*\z/gc;
    pos($$bref) = undef;
    return if $only_breaks or $start > $line_start;
    return ($start, $end);
}

# True if $$bref from $start to $end is $$oref: the same bytes, or those
# bytes and a "\n" when $$oref ends without a line break (wrap() adds one
# before the next delimiter).  Compared a megabyte at a time.
sub _same_bytes {
    my ($bref, $start, $end, $oref) = @_;
    my $olen = length $$oref;
    unless ($end - $start == $olen) {
        return 0
            unless $olen
            and $end - $start == $olen + 1
            and substr($$oref, -1) !~ /[\r\n]/
            and substr($$bref, $end - 1, 1) eq "\n";
    }
    for (my $i = 0; $i < $olen; $i += 1 << 20) {
        my $n = $olen - $i < 1 << 20 ? $olen - $i : 1 << 20;
        return 0
            unless substr($$bref, $start + $i, $n) eq substr($$oref, $i, $n);
    }
    return 1;
}

# Anonymous lists and resends from the archive start a new chain: the
# outbound signer then adds a fresh m=1.
sub _strip_chain {
    my $message = shift;
    $message->delete_header($_)
        for 'DKIM2-Signature', 'Message-Instance', 'X-DKIM2-Info';
}

# DKIM2 implementation metadata -- update DKIM2_DATE on each change.
use constant DKIM2_DRAFT    => 'ietf-dkim-dkim2-spec-06';
use constant DKIM2_REPO     => 'github.com/brong/sympa';
use constant DKIM2_DATE     => '2026-10-08';
use constant DKIM2_SOFTWARE => 'sympa';

# X-DKIM2-Info value per draft-gondwana-dkim2-debug-header-01: a tag-list in
# the DKIM2 syntax, every tag (the last included) followed by ";".  A ";" has
# no escape and ends a tag, so one inside a value becomes ",".  Folded only
# after a ";" or a "," (never inside a token, so the hn= list breaks between
# names); X-* fields are excluded from the header hash, so folding it cannot
# affect a signature.  Returns the value alone, folded with "\n\t".
sub _dkim2_info {
    my ($action, %extra) = @_;
    my @tags = ("draft=" . DKIM2_DRAFT, "repo=" . DKIM2_REPO,
                "date=" . DKIM2_DATE, "sw=" . DKIM2_SOFTWARE, "action=$action");
    push @tags, "$_=$extra{$_}" for grep { defined $extra{$_} } sort keys %extra;
    my $val = join ' ', map { (my $t = $_) =~ s/;/,/g; "$t;" } @tags;
    # fold_header() budgets for the field name, so fold with it attached.
    my $folded = Mail::DKIM2::Common::fold_header("X-DKIM2-Info: $val", undef,
        delimiters_only => 1);
    $folded =~ s/\AX-DKIM2-Info:\s*//;
    $folded =~ s/\r\n/\n/g;
    return $folded;
}

# The header block of $message as calculate() takes it: the fields as
# they go on the wire, a blank line, CRLF line ends, no body.
sub _header_block {
    my $message = shift;
    (my $h = $message->{_head}->as_string . "\n") =~ s/\r?\n/\r\n/g;
    return $h;
}

# (count, comma-separated lower-cased names) of the header fields the
# DKIM2 header hash covers, from an Email::MIME.
sub _header_list_for_hash {
    my $em = shift;
    my @names;
    for my $h (sort { lc($a) cmp lc($b) } $em->header_names) {
        next if Mail::DKIM2::Common::should_skip($h);
        push @names, (lc $h) x scalar(my @v = $em->header_raw($h));
    }
    return (scalar(@names), join(',', @names));
}

# Add $mi as the top Message-Instance, with the X-DKIM2-Info describing it
# directly above.  fold_header returns the field folded with "\r\n\t" and no
# trailing newline; MIME::Head wants "\n\t" continuations and no trailing
# newline.  hc/hn come from the header block with the new instance in place;
# the body is not parsed.
sub _prepend_instance {
    my ($message, $mi) = @_;
    my $folded = Mail::DKIM2::Common::fold_header(
        'Message-Instance: ' . $mi->as_string);
    $folded =~ s/\AMessage-Instance:\s*//;
    $folded =~ s/\r\n/\n/g;
    $message->{_head}->add('Message-Instance', $folded, 0);
    delete $message->{_entity_cache};
    my ($hc, $hn) = _header_list_for_hash(
        Mail::DKIM2::Common::parse_mime(_header_block($message)));
    my $m = $mi->get_tag('m');
    $message->{_head}->add('X-DKIM2-Info',
        _dkim2_info("mi-m=$m", hc => $hc, hn => $hn), 0);
    delete $message->{_entity_cache};
}

# Never decorated: wrapping would break the signature or encryption.
my @SKIP_TYPES = qw(multipart/signed multipart/encrypted
    application/pkcs7-mime application/x-pkcs7-mime);

# decorate() for DKIM2 lists: instead of editing the body, wrap it verbatim
# as the middle part of a multipart/mixed between the header and footer
# parts.  The body is never parsed or re-encoded, so it can be copied back
# out line for line.  Records in $message->{_dkim2_body_lines} the 1-based
# lines [first, last] of the original body inside the new body ([] when the
# original body is empty).  Leaves the message alone when there is nothing
# to add or the type is in @SKIP_TYPES.
sub wrap {
    my ($message, $list, $rcpt, %options) = @_;
    my $mode = $options{mode} || '';
    my $head = $message->{_head};

    my $type = lc($head->mime_type || 'text/plain');
    return 1 if grep { $type eq $_ } @SKIP_TYPES;

    my $data = $mode ? $message->_personalize_attrs : undef;
    my @before = _parts($list, $rcpt, $data, $mode, 'header');
    my @after  = (
        _parts($list, $rcpt, $data, $mode, 'footer'),
        _parts($list->{'domain'}, $rcpt, $data, $mode, 'global footer', $list)
    );
    return 1 unless @before or @after;

    # The body is used through a reference and copied only into the new
    # body: it can be large, and this runs once per recipient.
    my $body     = defined $message->{_body} ? \$message->{_body} : \'';
    my $boundary = _boundary($$body, @before, @after);

    # The original part: the top-level MIME fields move to it, verbatim.
    # Content-Length no longer describes anything, so it goes.
    # header() gives the field lines in order, folded, each ending "\n".
    my @fields = grep {/\Acontent-/i} @{$head->header};
    my $orig_part = join '', grep { !/\Acontent-length:/i } @fields;
    my %tags = map { /\A([^:]+):/ ? (lc $1 => 1) : () } @fields;
    my $cte = lc(($orig_part =~ /^content-transfer-encoding:\s*(\S+)/mi)[0]
            // '7bit');

    my $pre = "This is a multi-part message in MIME format.\n";
    $pre .= "\n--$boundary\n$_" for @before;
    $pre .= "\n--$boundary\n$orig_part\n";
    # The body starts on the line after the last newline of $pre.  Lines
    # are counted by "\n", which also ends each CRLF line, so the count
    # matches the CRLF wire form.
    my $first  = ($pre =~ tr/\n//) + 1;
    my $open   = length $$body && substr($$body, -1) ne "\n";
    my $nlines = ($$body =~ tr/\n//) + ($open ? 1 : 0);
    # The delimiter's own line break: the body's final newline (if any)
    # stays part of the body, as received.
    my $post = $open ? "\n" : '';
    $post .= "\n--$boundary\n$_" for @after;
    $post .= "\n--$boundary--\n";

    # The new header is built on a copy, so a failure anywhere above or
    # here leaves the message as it was.
    my $new_head = $head->dup;
    $new_head->delete($_) for keys %tags;
    $new_head->replace('MIME-Version', '1.0')
        unless $new_head->count('MIME-Version');
    $new_head->replace('Content-Type',
        sprintf 'multipart/mixed; boundary="%s"', $boundary);
    if ($cte eq 'binary') {
        $new_head->replace('Content-Transfer-Encoding', 'binary');
    } elsif ($cte eq '8bit' or grep {/[^\x00-\x7F]/} $$body, @before, @after)
    {
        $new_head->replace('Content-Transfer-Encoding', '8bit');
    }

    $message->{_head} = $new_head;
    $message->{_body} = $pre . $$body . $post;
    delete $message->{_entity_cache};
    $message->{_dkim2_body_lines} =
        $nlines ? [$first, $first + $nlines - 1] : [];
    return 1;
}

# The MIME parts (header fields, blank line, body; "\n" line ends; final
# "\n") for one kind of decoration file, as stock decorate() would choose
# and personalise it: "message_<kind>.mime" (a MIME entity) when
# footer_type is mime and it exists, else "message_<kind>" (text).
# Dies on failure; wrap() changes nothing then.
sub _parts {
    my ($that, $rcpt, $data, $mode, $kind, $list) = @_;
    $list ||= $that;
    (my $base = "message_$kind") =~ s/ /_/g;    # message_global_footer

    # As stock: with footer_type mime, an existing .mime file is used even
    # when empty (then nothing is added); no fallback to the text file.
    my $mime = ($list->{'admin'}{'footer_type'} || '') eq 'mime'
        && Sympa::search_fullpath($that, "$base.mime");
    if ($mime) {
        return () unless -s $mime;
        my $parser = MIME::Parser->new;
        $parser->output_to_core(1);
        $parser->tmp_dir($Conf::Conf{'tmpdir'});
        my $part = eval { $parser->parse_open($mime) };
        unless ($part) {
            $log->syslog('err', 'Failed to parse MIME data %s: %s',
                $mime, $parser->last_error || $EVAL_ERROR);
            return ();
        }
        if ($mode
            and not defined Sympa::Message::_merge_msg($part, $list, $rcpt,
                $data)) {
            $log->syslog('info', 'Error personalizing %s', $kind);
            return ();
        }
        my $t = $part->stringify;
        $t =~ s/\r\n/\n/g;
        $t .= "\n" unless $t =~ /\n\z/;
        return ($t);
    }

    my $file = Sympa::search_fullpath($that, $base);
    my $t = Sympa::Message::_footer_text($file, $list, $rcpt, $data,
        mode => $mode, type => $kind) // '';
    return () unless length $t;
    $t .= "\n" unless $t =~ /\n\z/;
    my $cte = $t =~ /[^\x00-\x7F]/ ? '8bit' : '7bit';
    return (  "Content-Type: text/plain; charset=UTF-8\n"
            . "Content-Transfer-Encoding: $cte\n"
            . "Content-Disposition: inline\n\n"
            . $t);
}

# A boundary occurring in none of the strings given (the body and the new
# parts; none is copied).
sub _boundary {
    while (1) {
        my $b = sprintf '=_dkim2_%08x%08x',
            int rand 0xffffffff, int rand 0xffffffff;
        return $b unless grep { index($_, $b) >= 0 } @_;
    }
}

1;
__END__

=encoding utf-8

=head1 NAME

Sympa::DKIM2 - DKIM2 Message-Instance support

=head1 SYNOPSIS

  # Spindle::ProcessIncoming, before S/MIME decryption:
  Sympa::DKIM2::ingress($message);

  # Sympa::Message::decorate() on a DKIM2 list:
  Sympa::DKIM2::wrap($message, $list, $rcpt, mode => $mode);

  # Spindle::ProcessOutgoing, once per packet and then per copy:
  my $ctx = Sympa::DKIM2::egress_context($message);
  Sympa::DKIM2::egress_add($message, $ctx, body_rewritten => $rewritten);

=head1 DESCRIPTION

Records what a list changed in each message as a DKIM2 Message-Instance
header field (draft-ietf-dkim-dkim2-spec-06), so DKIM2 verifiers downstream
can undo the list's changes and check the signatures of earlier hops.  The
DKIM2-Signature itself is added by the MTA.

Everything here is gated on the list parameter C<dkim2_message_instance>.
The header block as received is carried through the spools in the
C<X-Sympa-DKIM2-Headers> pseudo-header (see L<Sympa::Message>).  Decoration
on a DKIM2 list wraps the original body in a C<multipart/mixed> instead of
editing it, so the body Recipe is a copy range; a body rewritten for any
other reason gets a null body Recipe.  Each instance Sympa adds has an
C<X-DKIM2-Info> debug field directly above it.

Requires Mail::DKIM2 0.15 or later, loaded on first use.  See
F<DKIM2-MESSAGE-INSTANCE.md> for the design.

=head2 Functions

=over

=item enabled ( $that )

True if C<$that> is a L<Sympa::List> with C<dkim2_message_instance> set to
C<on> and Mail::DKIM2 0.15 or later can be loaded.  If the switch is on but
the module cannot be loaded or is too old, returns false and logs at C<err>
(once per process).

=item anonymous ( $list )

True if the list has C<anonymous_sender> set.  Such lists keep no record of
the original message and start a new chain at egress.

=item ingress ( $message )

Run once per message at ingress, before S/MIME decryption or any other
change.  On a DKIM2 list that is not anonymous: adds C<m=1> describing the
message as received unless it already carries a Message-Instance, and
saves the header block in C<< $message->{dkim2_headers} >>, which is
spooled as the pseudo-header.  Does nothing if the message already has a
saved header block (requeued from F<bad/>, say).  Logs and carries on on
failure.

=item wrap ( $message, $list, $rcpt, [ mode =E<gt> $mode ] )

Decoration for DKIM2 lists, called by C<Sympa::Message::decorate()>.
Makes the body the middle part of a C<multipart/mixed> between the list's
header part and its footer and global footer parts, moving the top-level
C<Content-*> fields to it and copying the body byte for byte.  Records the
original body's lines in the new body for egress.  Leaves the message alone
when there is nothing to add or it is C<multipart/signed>,
C<multipart/encrypted> or opaque S/MIME.  Dies on failure, with the message
unchanged.  Returns true otherwise.

=item egress_context ( $message )

Run once per packet in ProcessOutgoing, before any per-recipient change.
Returns C<undef> if nothing is to be added (switch off, no saved header
block, or a saved block that does not verify; a missing block is logged at
C<info> if the message carries a DKIM2 chain, else at C<debug>), C<< {strip =E<gt> 1} >> for
anonymous lists and resends from the archive, or a context for
L</egress_add>: the saved block, whether the body is still the one the top
instance hashed, and that hash.

=item egress_add ( $message, $context, [ body_rewritten =E<gt> 1 ] )

Run for each copy, after every other transformation and before DKIM and
ARC signing.  With a C<strip> context removes C<DKIM2-Signature>,
C<Message-Instance> and C<X-DKIM2-Info>.  Otherwise removes C<Bcc> and
C<Resent-Bcc> and adds the next Message-Instance, with its C<X-DKIM2-Info>
above it.  The body Recipe is null if the body changed before the packet,
C<body_rewritten> is set, or decoration fell back to editing the body;
otherwise it is the copy range recorded by L</wrap>, or none, provided that
it really gives back the received body.  Adds nothing if nothing changed.
Never dies.

=back

=head1 SEE ALSO

L<Sympa::Message>, L<Sympa::Spindle::ProcessIncoming>,
L<Sympa::Spindle::ProcessOutgoing>.

=cut
