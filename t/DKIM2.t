# -*- indent-tabs-mode: nil; -*-
# DKIM2 Message-Instance support. Needs Mail::DKIM2 (interop perl/lib or
# CPAN) on PERL5LIB; without it the test fails rather than skipping.
use strict; use warnings;
use English qw(-no_match_vars);
use File::Temp qw(tempdir);
use Test::More;
use Conf; use Sympa::ConfDef; use Sympa::Log; use Sympa::Message;
use Sympa::Config::Schema;
use Sympa::DKIM2; use Sympa::Spindle::ProcessArchive;
use Mail::DKIM2::MessageInstance; use Mail::DKIM2::Common;
use MIME::Base64 qw(encode_base64 decode_base64);
use List::Util ();

Sympa::Log->instance->{log_to_stderr} = 'err';
%Conf::Conf = (domain => 'mail.example.org', listmaster => 'lm@example.org',
               tmpdir => tempdir(CLEANUP => 1));
for my $p (grep { $_->{name} and exists $_->{default} } @Sympa::ConfDef::params) {
    $Conf::Conf{$p->{name}} //= $p->{default};
}
our %FILES; my $fdir = tempdir(CLEANUP => 1);
# Each call writes a new file, so "local %FILES" undoes a set_file.
my $fseq = 0;
sub set_file { my ($n, $c) = @_; my $p = "$fdir/" . ++$fseq . "-$n";
               open my $f, '>:raw', $p or die; print $f $c; close $f;
               $FILES{$n} = $p }
{ no warnings 'redefine';
  *Sympa::search_fullpath = sub { $FILES{$_[1]} };
  *Sympa::List::update_stats = sub { 1 };
}
sub list { my %a = @_; bless { name => 'test', domain => 'mail.example.org',
    admin => { footer_type => 'mime', dkim2_message_instance => 'on', %a } }
    => 'Sympa::List' }

subtest 'switch parameter' => sub {
    my %p = %{ $Sympa::Config::Schema::pinfo{dkim2_message_instance} || {} };
    ok %p, 'defined';
    is_deeply $p{format}, ['on', 'off'], 'on/off';
    is $p{default}, 'off', 'default off';
    is_deeply $p{context}, [qw(list domain site)], 'list/domain/site';
};

my $plain = "From: a\@example.org\nTo: test\@mail.example.org\nSubject: hi\nMessage-ID: <1\@example.org>\n\nhello\n";

subtest 'enabled' => sub {
    ok Sympa::DKIM2::enabled(list()), 'on';
    ok !Sympa::DKIM2::enabled(list(dkim2_message_instance => 'off')), 'off';
    ok !Sympa::DKIM2::enabled('mail.example.org'), 'robot context';
};

subtest 'enabled: Mail::DKIM2 older than 0.15 counts as missing' => sub {
    my @err;
    no warnings 'redefine';
    local *Sympa::Log::syslog = sub { push @err, $_[2] if $_[1] eq 'err' };
    local $Mail::DKIM2::MessageInstance::VERSION = '0.14';
    ok !Sympa::DKIM2::enabled(list()), 'not enabled';
    my $m = Sympa::Message->new($plain, context => list());
    Sympa::DKIM2::ingress($m);
    ok !$m->{_head}->count('Message-Instance') && !defined $m->{dkim2_headers},
        'ingress adds nothing';
    is scalar(grep {/cannot be loaded/} @err), 1, 'logged once per process';
};

subtest 'pseudo-header round trip' => sub {
    my $m = Sympa::Message->new($plain, context => list());
    $m->{dkim2_headers} = "From: a\@example.org\nSubject: hi\n";
    my $s = $m->to_string;
    like $s, qr/^X-Sympa-DKIM2-Headers: [A-Za-z0-9+\/=]+\n/m, 'serialised';
    unlike $m->as_string, qr/X-Sympa-DKIM2/, 'not in the message proper';
    my $back = Sympa::Message->new($s, context => list());
    is $back->{dkim2_headers}, $m->{dkim2_headers}, 'decoded';
    is $back->dup->{dkim2_headers}, $m->{dkim2_headers}, 'dup keeps it';
};

subtest 'as_rfc822_string' => sub {
    my $m = Sympa::Message->new($plain, context => list());
    my $r = $m->as_rfc822_string;
    unlike $r, qr/(?<!\r)\n/, 'CRLF only';
    like $r, qr/\r\n\r\nhello\r\n\z/, 'body';
    unlike $r, qr/^(Return-Path|X-Sympa-)/m, 'no pseudo-headers';
};

subtest 'ingress' => sub {
    my $m = Sympa::Message->new($plain, context => list());
    Sympa::DKIM2::ingress($m);
    is $m->{_head}->count('Message-Instance'), 1, 'm=1 added';
    like $m->{dkim2_headers}, qr/^Message-Instance: m=1;/m, 'saved after m=1';
    like $m->{_head}->as_string, qr/^Message-Instance: [^\n]*\n\t\S/m,
        'long m=1 folded with a tab continuation';
    unlike $m->{_head}->as_string, qr/\n\n|\r/, 'no blank lines or CR in header';
    my ($ok, $err) = Mail::DKIM2::MessageInstance->chain_verifies($m->as_rfc822_string);
    ok $ok, 'm=1 verifies' or diag $err;

    my $again = Sympa::Message->new($m->as_string, context => list());
    Sympa::DKIM2::ingress($again);
    is $again->{_head}->count('Message-Instance'), 1, 'existing instance kept';

    # Requeued from bad/: the saved block comes back through the spool and
    # ingress leaves it alone, though the message itself has changed.
    my $requeued = Sympa::Message->new($m->to_string, context => list());
    $requeued->replace_header('Subject', 'changed after ingress');
    Sympa::DKIM2::ingress($requeued);
    is $requeued->{dkim2_headers}, $m->{dkim2_headers},
        'requeued: saved header block kept';

    my $off = Sympa::Message->new($plain, context => list(dkim2_message_instance => 'off'));
    Sympa::DKIM2::ingress($off);
    ok !$off->{_head}->count('Message-Instance') && !defined $off->{dkim2_headers}, 'off: nothing';

    my $anon = Sympa::Message->new($plain, context => list(anonymous_sender => 'anon@mail.example.org'));
    Sympa::DKIM2::ingress($anon);
    ok !defined $anon->{dkim2_headers}, 'anonymous: no saved headers';
};

# Ingress, spool round trip, decorate; then check the Recipe built from the
# recorded lines undoes to the original body hash.
sub wrapped {
    my ($raw, %listopts) = @_;
    my $l = list(%listopts);
    my $m = Sympa::Message->new($raw, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l)->dup;
    $b->decorate($l, undef);
    return $b;
}
# Copy the recorded lines out of the wire (CRLF) form of the wrapped body,
# as a verifier applying the Recipe would.
sub orig_body_lines_ok {
    my ($b, $raw) = @_;
    my ($first, $last) = @{ $b->{_dkim2_body_lines} || [] };
    (my $orig = $raw) =~ s/\A.*?\r?\n\r?\n//s;
    (my $wire = $b->as_rfc822_string) =~ s/\A.*?\r\n\r\n//s;
    my @lines = split /\r\n/, $wire, -1;
    my $copied = defined $first ? join("\r\n", @lines[$first-1 .. $last-1]) . "\r\n" : '';
    is Mail::DKIM2::MessageInstance::body_digest_raw($copied),
       Mail::DKIM2::MessageInstance::body_digest_raw($orig), 'copy range is the original body';
}

set_file('message_footer', "-- \nfooter text\n");
set_file('message_header', "header text\n");

subtest 'wrap: text/plain with header and footer' => sub {
    my $b = wrapped($plain);
    like $b->get_header('Content-Type'), qr{^multipart/mixed;\s*boundary=}i, 'outer multipart/mixed';
    like $b->{_body}, qr/header text\n.*hello\n.*footer text\n/s, 'order';
    orig_body_lines_ok($b, $plain);
};

subtest 'wrap: no final newline, empty body, boundary collision, 8bit' => sub {
    for my $case (
        ["From: a\@x\nSubject: s\n\nno newline", 'no final newline'],
        ["From: a\@x\nSubject: s\n\n", 'empty body'],
        ["From: a\@x\nSubject: s\n\n--=_dkim2_0000\nx\n", 'boundary-like line'],
        ["From: a\@x\nSubject: s\nContent-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\ncaf\xe9\n", '8bit'],
    ) {
        my ($raw, $name) = @$case;
        my $b = wrapped($raw);
        my ($bd) = $b->get_header('Content-Type') =~ /boundary="?([^";]+)/;
        ok index($raw, $bd) < 0, "$name: boundary not in body";
        orig_body_lines_ok($b, $raw);
        like $b->get_header('Content-Transfer-Encoding') // '', qr/^8bit$/i, "$name: outer 8bit"
            if $name eq '8bit';
    }
};

subtest 'wrap: CRLF body, trailing blank lines, leading blank line' => sub {
    for my $case (
        ["From: a\@x\r\nSubject: s\r\n\r\nline one\r\nline two\r\n", 'CRLF'],
        ["From: a\@x\nSubject: s\n\nbody\n\n\n\n", 'trailing blank lines'],
        ["From: a\@x\nSubject: s\n\n\n\nafter blanks\n", 'leading blank lines'],
        ["From: a\@x\nSubject: s\n\n\n", 'body is one blank line'],
    ) {
        my ($raw, $name) = @$case;
        my $b = wrapped($raw);
        ok defined $b->{_dkim2_body_lines}, "$name: wrapped";
        orig_body_lines_ok($b, $raw);
    }
    my $b = wrapped("From: a\@x\nSubject: s\n\nbody\n\n\n\n");
    my ($first, $last) = @{ $b->{_dkim2_body_lines} || [0, 0] };
    is $last - $first + 1, 4, 'trailing blank lines are inside the range';
    my $e = wrapped("From: a\@x\nSubject: s\n\n");
    is_deeply $e->{_dkim2_body_lines}, [], 'empty body: []';
};

subtest 'wrap: header kept intact, Content-* moved to the original part' => sub {
    my $raw = "From: a\@x\nTo: t\@mail.example.org\nSubject: s\nMIME-Version: 1.0\n"
        . "Content-Length: 7\nContent-Type: text/plain;\n\tcharset=\"iso-8859-1\";\n\tformat=flowed\n"
        . "Content-Transfer-Encoding: quoted-printable\nContent-Language: fr\n"
        . "X-Other: kept\n\ncaf=E9\n";
    my $b = wrapped($raw);
    my $h = $b->{_head};
    is $h->count('MIME-Version'), 1, 'one MIME-Version';
    is $h->count('Content-Type'), 1, 'one Content-Type';
    ok !$h->count('Content-Transfer-Encoding'), 'no outer CTE for a 7bit wrap';
    ok !$h->count('Content-Language'), 'Content-Language moved';
    ok !$h->count('Content-Length'), 'Content-Length dropped';
    is $b->get_header('X-Other'), 'kept', 'other fields kept';
    is $h->count('Message-Instance'), 1, 'Message-Instance kept';
    my @tags = grep { !/^(content-|mime-version)/i } $h->as_string =~ /^([^\s:]+):/mg;
    is_deeply [@tags], [qw(X-DKIM2-Info Message-Instance From To Subject X-Other)], 'order of other fields kept';
    like $b->{_body}, qr/\n--\S+\nContent-Type:\ text\/plain;\n\tcharset="iso-8859-1";\n\tformat=flowed\n
        Content-Transfer-Encoding:\ quoted-printable\nContent-Language:\ fr\n\ncaf=E9\n\n--/x,
        'original part: fields in order, then the body verbatim';
    my $e = $b->as_entity;
    ok !grep({ $_->head->count('Content-Length') } $e->parts), 'no Content-Length in parts';
    my ($orig) = grep { ($_->head->get('Content-Language') // '') =~ /fr/ } $e->parts;
    ok $orig, 'original part found';
    is $orig->head->get('Content-Type'), "text/plain;\n\tcharset=\"iso-8859-1\";\n\tformat=flowed\n",
        'folded Content-Type moved verbatim';
    is $orig->bodyhandle->as_string, "caf\xe9\n", 'original part decodes';
    is scalar($e->parts), 3, 'header, original, footer';
    orig_body_lines_ok($b, $raw);
};

subtest 'wrap: multipart original' => sub {
    my $raw = "From: a\@x\nSubject: s\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"alt\"\n\n"
        . "preamble\n--alt\nContent-Type: text/plain\n\nplain\n--alt\nContent-Type: text/html\n\n<p>html</p>\n--alt--\n";
    my $b = wrapped($raw);
    my @p = $b->as_entity->parts;
    is scalar(@p), 3, 'three parts';
    is $p[1]->effective_type, 'multipart/alternative', 'original kept as a part';
    is scalar($p[1]->parts), 2, 'with its own parts';
    orig_body_lines_ok($b, $raw);
};

subtest 'wrap: only header, only footer, nothing' => sub {
    local %FILES = %FILES;
    delete $FILES{message_footer};
    my $b = wrapped($plain);
    like $b->{_body}, qr/header text\n.*\n\nhello\n\n--\S+--\n\z/s, 'header only';
    orig_body_lines_ok($b, $plain);
    delete $FILES{message_header};
    my $n = wrapped($plain);
    ok !defined $n->{_dkim2_body_lines}, 'nothing to add: untouched';
    unlike $n->get_header('Content-Type') // '', qr/multipart/, 'not wrapped';
};

subtest 'wrap: .mime footer used as a MIME part' => sub {
    local %FILES = %FILES;
    set_file('message_footer.mime', "Content-Type: text/html; charset=UTF-8\n\n<p>html footer</p>\n");
    my $b = wrapped($plain);
    like $b->{_body}, qr/hello\n\n--\S+\nContent-Type: text\/html; charset="?UTF-8"?\n.*<p>html footer<\/p>\n\n--\S+--\n\z/s,
        '.mime footer is the last part';
    unlike $b->{_body}, qr/footer text/, 'text footer not used';
    my @p = $b->as_entity->parts;
    is $p[-1]->effective_type, 'text/html', 'parses as text/html';
    orig_body_lines_ok($b, $plain);
    my $a = wrapped($plain, footer_type => 'append');
    like $a->{_body}, qr/footer text/, 'append: .mime ignored';
};

subtest 'wrap: personalised footers' => sub {
    local %FILES = %FILES;
    set_file('message_footer', "plain [% listname %]\n");
    set_file('message_global_footer.mime',
        "Content-Type: text/plain; charset=UTF-8\n\nglobal [% domain %]\n");
    my $l = list();
    my $m = Sympa::Message->new($plain, context => $l);
    Sympa::DKIM2::ingress($m);
    $m->decorate($l, undef, mode => 'footer');
    like $m->{_body}, qr/hello\n\n--\S+\n.*plain test\n\n--\S+\n.*global mail\.example\.org\n\n--\S+--\n\z/s,
        'text and .mime footers personalised, in order';
    orig_body_lines_ok($m, $plain);
};

subtest 'wrap: append footer_type still wraps' => sub {
    my $b = wrapped($plain, footer_type => 'append');
    like $b->get_header('Content-Type'), qr{^multipart/mixed}i, 'wrapped';
    orig_body_lines_ok($b, $plain);
};

subtest 'wrap: skipped types and switch off' => sub {
    for my $ct ('multipart/signed; protocol="application/pgp-signature"; boundary=b',
                'application/pkcs7-mime; smime-type=signed-data') {
        my $raw = "From: a\@x\nSubject: s\nMIME-Version: 1.0\nContent-Type: $ct\n\nbody\n";
        my $b = wrapped($raw);
        ok !defined $b->{_dkim2_body_lines}, "$ct: no body lines";
        is $b->get_header('Content-Type'), $ct, "$ct: Content-Type unchanged";
        is $b->{_body}, "body\n", "$ct: body unchanged";
    }
    my $off = wrapped($plain, dkim2_message_instance => 'off');
    ok !defined $off->{_dkim2_body_lines}, 'off: stock decorate ran';
    like $off->get_header('Content-Type'), qr{^multipart/mixed}i, 'off: stock MIME footer added';
    my $anon = wrapped($plain, anonymous_sender => 'anon@mail.example.org');
    ok !defined $anon->{_dkim2_body_lines}, 'no saved headers (anonymous): stock decorate ran';
};

subtest 'wrap: empty .mime file adds nothing, no fallback to the text file' => sub {
    local %FILES = %FILES;
    set_file('message_footer.mime', '');
    my $b = wrapped($plain);
    unlike $b->{_body}, qr/footer text/, 'text footer not used';
    like $b->{_body}, qr/header text\n.*\n\nhello\n\n--\S+--\n\z/s, 'header only';
    orig_body_lines_ok($b, $plain);
    set_file('message_header.mime', '');
    my $n = wrapped($plain);
    ok !defined $n->{_dkim2_body_lines}, 'both .mime empty: nothing to add';
    is $n->{_body}, "hello\n", 'body untouched';
};

subtest 'wrap: failure leaves the message alone; decorate falls back to stock' => sub {
    # A die after the parts are built, while the new header is assembled.
    my $l = list();
    my $m = Sympa::Message->new($plain, context => $l);
    Sympa::DKIM2::ingress($m);
    my ($head_before, $body_before) = ($m->{_head}->as_string, $m->{_body});
    {
        no warnings qw(redefine once);
        local *MIME::Head::replace = sub { die "boom\n" };
        ok !eval { Sympa::DKIM2::wrap($m, $l, undef); 1 }, 'wrap died';
    }
    is $m->{_head}->as_string, $head_before, 'head unchanged';
    is $m->{_body}, $body_before, 'body unchanged';
    ok !defined $m->{_dkim2_body_lines}, 'no body lines';

    # decorate() survives a wrap failure and decorates the stock way.
    my $err = '';
    {
        no warnings 'redefine';
        local *Sympa::DKIM2::_boundary = sub { die "boom\n" };
        local *STDERR; open STDERR, '>', \$err or die;
        $m->decorate($l, undef);
    }
    like $err, qr/^err .*DKIM2 wrap failed for .*<1\@example\.org>.*: boom$/m, 'logged at err';
    ok $m->{_dkim2_body_rewritten}, 'body marked rewritten';
    ok !defined $m->{_dkim2_body_lines}, 'no body lines';
    like $m->get_header('Content-Type'), qr{^multipart/mixed}i, 'stock MIME footer added';
    is $m->{_head}->count('Content-Type'), 1, 'one Content-Type';
    my @p = $m->as_entity->parts;
    like $p[0]->bodyhandle->as_string, qr/header text/, 'stock header part';
    like $p[1]->bodyhandle->as_string, qr/^hello/, 'original';
    like $p[-1]->bodyhandle->as_string, qr/footer text/, 'stock footer part';
    is $m->{_head}->count('Message-Instance'), 1, 'Message-Instance kept';
};

# Ingress -> spool -> (mod) -> decorate -> egress; returns the wire text
# (CRLF), and in list context also the message.  Options besides the list's:
#   shelved   => [flags] set on the bulk-spool message
#   pre       => sub run before the bulk spool (as ToList does for modes)
#   decorate  => 0 to skip decorate (notice mode)
#   post      => sub run after decorate, before egress_add
#   rewritten => body_rewritten passed to egress_add
sub through {
    my ($raw, $mod, %listopts) = @_;
    my %o = map { $_ => delete $listopts{$_} }
        qw(shelved pre decorate post rewritten);
    my $l = list(%listopts);
    my $m = Sympa::Message->new($raw, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l);
    if ($o{pre}) {
        $o{pre}->($b, $l);
        $b = Sympa::Message->new($b->to_string, context => $l);
    }
    $b->{shelved}{$_} = 1 for @{$o{shelved} || []};
    my $ctx = Sympa::DKIM2::egress_context($b);
    my $one = $b->dup;
    $mod->($one) if $mod;
    $one->decorate($l, undef) if $o{decorate} // 1;
    $o{post}->($one) if $o{post};
    Sympa::DKIM2::egress_add($one, $ctx,
        body_rewritten => $o{rewritten} ? 1 : 0);
    my $w = $one->as_rfc822_string;
    return wantarray ? ($w, $one) : $w;
}
sub chain_ok { my ($w, $name) = @_;
    my ($ok, $err) = Mail::DKIM2::MessageInstance->chain_verifies($w);
    ok $ok, $name or diag $err }
sub top_recipe { my $w = shift;
    my ($v) = $w =~ /^Message-Instance: (m=2;.*?)\r\n(?![ \t])/ms or return;
    Mail::DKIM2::MessageInstance->parse($v) }

subtest 'egress: wrap verifies' => sub {
    my $w = through($plain, sub { $_[0]->add_header('List-Id', '<test.mail.example.org>');
                                  $_[0]->replace_header('Subject', '[test] hi') });
    chain_ok($w, 'wrapped + headers changed');
    ok !top_recipe($w)->unrecoverable, 'body recoverable';
    cmp_ok length(($w =~ /^(Message-Instance: m=2;.*?)\r\n(?![ \t])/ms)[0]), '<', 2000, 'small header';
};

subtest 'egress: body changed -> null' => sub {
    my ($w, $err) = ('', '');
    { local *STDERR; open STDERR, '>', \$err or die;
      $w = through($plain, sub { $_[0]->{_body} = "rewritten\n"; delete $_[0]->{_entity_cache} }) }
    like $err, qr/^notice .*body of .* changed after ingress; null body Recipe/m, 'logged';
    ok top_recipe($w)->unrecoverable, 'b null';
    chain_ok($w, 'header history still verifies');
};

subtest 'egress: original part edited in place after decorate -> null' => sub {
    my ($w, $err) = ('', '');
    { local *STDERR; open STDERR, '>', \$err or die;
      $w = through($plain, undef, post => sub {
          $_[0]->{_body} =~ s/^hello$/HELLO/m or die 'no hello';
          delete $_[0]->{_entity_cache} }) }
    like $err, qr/^notice .*body of .* changed after ingress; null body Recipe/m, 'logged';
    ok top_recipe($w)->unrecoverable, 'same length, same lines: still b null';
    chain_ok($w, 'header history still verifies');
};

subtest 'egress: original body without a final newline' => sub {
    (my $nonl = $plain) =~ s/\n\z//;
    for my $end ('', "\r") {
        my ($w, $err) = ('', '');
        { local *STDERR; open STDERR, '>', \$err or die;
          $w = through($nonl . $end) }
        my $mi = top_recipe($w);
        ok $mi, 'instance' and is !!$mi->unrecoverable, !!length $end,
            length $end ? 'lone CR at the end: b null' : 'body recoverable';
        is $err =~ /null body Recipe/ ? 1 : 0, length $end ? 1 : 0,
            length $end ? 'logged' : 'nothing logged';
        chain_ok($w, 'verifies');
    }
};

subtest 'egress: no saved headers -> nothing, no error' => sub {
    my $l = list();
    for my $c (
        [ 'plain post', '', 'debug' ],
        [ 'post with a Message-Instance',
          "Message-Instance: m=1; h=sha256:x:y;\n", 'info' ],
        [ 'post with a DKIM2-Signature',
          "DKIM2-Signature: i=1; d=example.org; fake\n", 'info' ],
    ) {
        my ($name, $extra, $level) = @$c;
        my $b = Sympa::Message->new($extra . $plain, context => $l);
        # Captured at the source: debug lines never reach STDERR here.
        my ($ctx, @logged) = (1);
        { no warnings 'redefine';
          local *Sympa::Log::syslog = sub { push @logged, [@_[1, 2]] };
          $ctx = Sympa::DKIM2::egress_context($b) }
        is $ctx, undef, "$name: no context";
        is_deeply [map { $_->[0] } grep { $_->[1] =~ /no saved header block/ }
                   @logged], [$level], "$name: logged once, at $level";
        Sympa::DKIM2::egress_add($b, undef);
        is $b->{_head}->count('Message-Instance'), $extra =~ /^Message/ ? 1 : 0,
            "$name: no instance added";
    }
};

subtest 'egress: Bcc removed and recorded' => sub {
    my $w = through("Bcc: x\@example.org\n$plain");
    unlike $w, qr/^Bcc:/mi, 'Bcc gone';
    chain_ok($w, 'verifies');
};

subtest 'egress: wrap fell back to stock decoration -> null' => sub {
    my ($w, $err) = ('', '');
    {
        no warnings 'redefine';
        local *Sympa::DKIM2::_boundary = sub { die "boom\n" };
        local *STDERR; open STDERR, '>', \$err or die;
        $w = through($plain);
    }
    like $err, qr/DKIM2 wrap failed/, 'wrap failed';
    like $w, qr/footer text/, 'stock footer';
    ok top_recipe($w)->unrecoverable, 'b null';
    chain_ok($w, 'header history still verifies');
};

subtest 'egress: body_rewritten option -> null' => sub {
    my $l = list();
    my $m = Sympa::Message->new($plain, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l);
    my $ctx = Sympa::DKIM2::egress_context($b);
    is $ctx->{unchanged}, 1, 'body unchanged since ingress';
    $b->decorate($l, undef);
    Sympa::DKIM2::egress_add($b, $ctx, body_rewritten => 1);
    ok top_recipe($b->as_rfc822_string)->unrecoverable, 'b null';
};

subtest 'egress: nothing changed -> no instance' => sub {
    local %FILES;    # no header or footer: decorate adds nothing
    my $w = through($plain);
    unlike $w, qr/^Message-Instance: m=2;/m, 'no m=2';
    like $w, qr/^Message-Instance: m=1;/m, 'm=1 kept';
    chain_ok($w, 'verifies');
};

subtest 'egress: undecorated, header changed -> body Recipe none' => sub {
    local %FILES;
    my $w = through($plain, sub { $_[0]->replace_header('Subject', '[test] hi') });
    my $mi = top_recipe($w);
    ok $mi, 'm=2 added';
    ok !$mi->unrecoverable, 'not null';
    ok !$mi->get_tag('rb'), 'no body Recipe';
    chain_ok($w, 'verifies');
};

subtest 'egress: saved header block tampered -> nothing, logged' => sub {
    my $l = list();
    my $m = Sympa::Message->new($plain, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l);
    $b->{dkim2_headers} =~ s/^Subject: hi$/Subject: forged/m;
    my $err = '';
    my $ctx;
    { local *STDERR; open STDERR, '>', \$err or die;
      $ctx = Sympa::DKIM2::egress_context($b) }
    is $ctx, undef, 'no context';
    like $err, qr/^err .*saved header block does not verify/m, 'logged';
};

subtest 'egress: switch off -> no context' => sub {
    my $b = Sympa::Message->new($plain, context => list(dkim2_message_instance => 'off'));
    $b->{dkim2_headers} = "From: a\@example.org\n";
    is Sympa::DKIM2::egress_context($b), undef, 'undef';
};

subtest 'egress: anonymous -> strip' => sub {
    my $b = Sympa::Message->new($plain, context => list(anonymous_sender => 'anon@mail.example.org'));
    is_deeply Sympa::DKIM2::egress_context($b), {strip => 1}, 'strip';
};

subtest 'egress: body changed before the packet -> unchanged 0, null' => sub {
    my $l = list();
    my $m = Sympa::Message->new($plain, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l);
    $b->{_body} = "changed in the spool\n";
    my $ctx = Sympa::DKIM2::egress_context($b);
    is $ctx->{unchanged}, 0, 'unchanged 0';
    $b->decorate($l, undef);
    Sympa::DKIM2::egress_add($b, $ctx);
    my $w = $b->as_rfc822_string;
    ok top_recipe($w)->unrecoverable, 'b null';
    chain_ok($w, 'header history still verifies');
};

subtest 'egress: empty original body wrapped' => sub {
    (my $empty = $plain) =~ s/hello\n\z//;
    my $w = through($empty);
    my $mi = top_recipe($w);
    ok $mi && !$mi->unrecoverable, 'body recoverable';
    chain_ok($w, 'verifies');
};

# __twist_one as the bulk daemon runs it, with the mailer, tracking DB,
# bounce address and DKIM signer stubbed; %shelved adds to the packet's
# shelved flags (MDN tracking, decorate, dkim_sign).  Returns the stored
# copies and Disposition-Notification-To as dkim_sign saw it.
sub twist_one {
    my ($b, $ctx, %shelved) = @_;
    local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /Too late to run INIT/ };
    require Sympa::Spindle::ProcessOutgoing;
    my (@stored, @dnt_at_sign);
    no warnings qw(redefine once);
    local *Sympa::Mailer::store = sub { push @stored, $_[1]->dup; 1 };
    local *Sympa::Tracking::find_notification_id_by_message = sub { 'ENVID' };
    local *Sympa::List::get_bounce_address = sub { 'test-owner@mail.example.org' };
    local *Sympa::Message::dkim_sign = sub {
        push @dnt_at_sign, scalar $_[0]->get_header('Disposition-Notification-To') };
    $b->{shelved} = {tracking => 'mdn', decorate => 1, dkim_sign => 1, %shelved};
    Sympa::Spindle::ProcessOutgoing::__twist_one($b, 'r@example.net',
        {}, {d => 'mail.example.org'}, 0, $ctx);
    return (\@stored, \@dnt_at_sign);
}

subtest 'ProcessOutgoing: per-recipient copy with MDN tracking verifies' => sub {
    my $l = list();
    my $m = Sympa::Message->new($plain, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l);
    my $ctx = Sympa::DKIM2::egress_context($b);
    my ($stored, $dnt) = twist_one($b, $ctx);
    is scalar @$stored, 1, 'stored';
    is_deeply $dnt, ['test-owner@mail.example.org'], 'MDN header set before DKIM signing';
    my $w = $stored->[0]->as_rfc822_string;
    like $w, qr/^Disposition-Notification-To: test-owner\@/m, 'MDN header';
    my $mi = top_recipe($w);
    ok $mi && !$mi->unrecoverable, 'm=2, body recoverable';
    ok $mi->get_tag('rh')->{'disposition-notification-to'}, 'MDN header in the header Recipe';
    chain_ok($w, 'verifies');
};

subtest 'ProcessOutgoing: no DKIM2 context -> stock order' => sub {
    my $l = list(dkim2_message_instance => 'off');
    my $b = Sympa::Message->new($plain, context => $l);
    my ($stored, $dnt) = twist_one($b, Sympa::DKIM2::egress_context($b));
    is_deeply $dnt, [undef], 'MDN header set after DKIM signing, as stock';
    like $stored->[0]->as_string, qr/^Disposition-Notification-To: test-owner\@/m, 'MDN header';
    is $stored->[0]{envelope_sender}, 'test-owner@mail.example.org', 'envelope sender';
    unlike $stored->[0]->as_string, qr/^Message-Instance:/m, 'no Message-Instance';
};

subtest 'anonymous list strips the chain, original From nowhere' => sub {
    my $signed_in = "DKIM2-Signature: i=1; d=example.org; fake\nMessage-Instance: m=1; h=sha256:x:y;\nX-DKIM2-Info: action=mi-m=1;\n"
                  . "From: Whistle Blower <whistle\@corp.example>\nOrganization: Corp Inc\nSubject: s\n\nbody\n";
    my $w = through($signed_in, sub {
        $_[0]->replace_header('From', 'anon@mail.example.org');
        $_[0]->delete_header('Organization');
    }, anonymous_sender => 'anon@mail.example.org');
    unlike $w, qr/^(DKIM2-Signature|Message-Instance|X-DKIM2-Info):/mi, 'chain stripped';
    unlike $w, qr/whistle|Corp Inc/i, 'original sender nowhere';
};

subtest 'resend from archive strips the chain' => sub {
    my $signed = "DKIM2-Signature: i=1; d=example.org; fake\n" . $plain;
    my $w = through($signed, undef, shelved => ['dkim2_strip']);
    unlike $w, qr/^(DKIM2-Signature|Message-Instance|X-DKIM2-Info):/mi,
        'stripped';
    my $m = Sympa::Message->new($plain, context => list());
    $m->{shelved}{dkim2_strip} = 1;
    like $m->to_string, qr/^X-Sympa-Shelved: .*dkim2_strip/m, 'flag is spooled';

    # ResendArchive sets the flag on DKIM2 lists only.
    require Sympa::Spindle::ResendArchive;
    for my $c ([on => 1], [off => 0]) {
        my ($sw, $want) = @$c;
        my $l = list(dkim2_message_instance => $sw);
        my $a = Sympa::Message->new($plain, context => $l);
        my $spindle = bless { context => $l, resent_by => 'r@example.org',
            message_id => Sympa::Tools::Text::canonic_message_id(
                $a->get_header('Message-Id')) },
            'Sympa::Spindle::ResendArchive';
        ok $spindle->_twist($a), "switch $sw: resent";
        is !!$a->{shelved}{dkim2_strip}, !!$want, "switch $sw: flag "
            . ($want ? 'set' : 'not set');
        unlike $a->to_string, qr/dkim2_strip/, "switch $sw: not spooled"
            unless $want;
    }
};

subtest '_recovers_body: copy range must fit the verifier line count' => sub {
    my $h = sub { Mail::DKIM2::MessageInstance::body_digest_raw(shift) };
    for my $body ("a\r\nb\r\n", "a\nb\n") {
        my $ctx = {body_hash => $h->($body)};
        ok Sympa::DKIM2::_recovers_body($body, [[1, 2]], $ctx),
            'whole body (1..2) recovered';
        $ctx = {body_hash => $h->("$body\r\n")};
        ok !Sympa::DKIM2::_recovers_body($body, [[1, 3]], $ctx),
            'range one past the last line is not a copy';
        ok !Sympa::DKIM2::_recovers_body("$body\n\n", [[1, 3]], $ctx),
            'nor is a trailing empty line';
    }
    my $orig = "x\ny\n";
    my $ctx = {body_hash => $h->($orig), orig_body => $orig};
    ok Sympa::DKIM2::_recovers_body("p\n${orig}f\n", [[2, 3]], $ctx),
        'byte-equal to the packet body';
    ok Sympa::DKIM2::_recovers_body("p\n${orig}f\n", [[2, 3]],
        {%$ctx, body_hash => 'not consulted'}),
        'byte-equal: decided by the compare, no hash';
    ok Sympa::DKIM2::_recovers_body("p\nx\ny\nf\n", [[2, 3]],
        {body_hash => 'not consulted', orig_body => "x\ny"}),
        'byte-equal but for the line break wrap() adds';
    ok !Sympa::DKIM2::_recovers_body("p\nx\ny\r\nf\n", [[2, 3]],
        {body_hash => $h->("x\ny\r"), orig_body => "x\ny\r"}),
        'a final lone CR is not given back';
    ok !Sympa::DKIM2::_recovers_body("p\nx\nY\nf\n", [[2, 3]], $ctx),
        'one byte different';
    ok Sympa::DKIM2::_recovers_body("p\r\nx\r\ny\r\nf\r\n", [[2, 3]], $ctx),
        'CRLF copy of an LF body: not byte-equal, hashes the same';
    ok !Sympa::DKIM2::_recovers_body("p\nx\ny\nf\n", [[1, 2]], $ctx),
        'wrong range';
    ok !Sympa::DKIM2::_recovers_body("", [[1, 1]], $ctx), 'empty body';
    ok Sympa::DKIM2::_recovers_body("p\n", [], {body_hash => $h->('')}),
        'empty original';
};

subtest 'egress: personalised footers on a large body, no MIME parse of the body' => sub {
    local %FILES;
    set_file('message_footer', "for [% user.email %]\n");
    no warnings qw(redefine once);
    local *Sympa::List::get_list_member =
        sub { +{email => $_[1], date => 0} };
    my $att = join '', map { encode_base64(pack('N*', $_ .. $_ + 40)) } 1 .. 2000;
    my $raw = "From: a\@example.org\nTo: test\@mail.example.org\nSubject: big\n"
        . "Message-ID: <big\@example.org>\nMIME-Version: 1.0\n"
        . "Content-Type: multipart/mixed; boundary=\"b1\"\n\n"
        . "--b1\nContent-Type: text/plain\n\nsee attached\n"
        . "--b1\nContent-Type: application/octet-stream\n"
        . "Content-Transfer-Encoding: base64\n\n$att--b1--\n";
    my $l = list();
    my $m = Sympa::Message->new($raw, context => $l);
    Sympa::DKIM2::ingress($m);
    my $pk = Sympa::Message->new($m->to_string, context => $l);
    my $ctx = Sympa::DKIM2::egress_context($pk);
    my $new = \&Email::MIME::new;
    my $digest = \&Mail::DKIM2::MessageInstance::body_digest_raw;
    for my $rcpt (map {"r$_\@example.net"} 1 .. 4) {
        my $one = $pk->dup;
        $one->decorate($l, $rcpt, mode => 'footer');
        my (@parsed, $hashed);
        {   local *Email::MIME::new = sub { push @parsed, length $_[1]; goto &$new };
            local *Mail::DKIM2::MessageInstance::body_digest_raw =
                sub { $hashed++; goto &$digest };
            Sympa::DKIM2::egress_add($one, $ctx);
        }
        cmp_ok(List::Util::max(0, @parsed), '<', 4096,
            "$rcpt: egress_add parsed header blocks only");
        is $hashed, 1, "$rcpt: body hashed once";
        my $w = $one->as_rfc822_string;
        like $w, qr/^for \Q$rcpt\E\r$/m, "$rcpt: personalised";
        my $mi = top_recipe($w);
        ok $mi && !$mi->unrecoverable, "$rcpt: body recoverable";
        chain_ok($w, "$rcpt: verifies");
    }
};

subtest 'custom archiver file has no DKIM2 pseudo-header' => sub {
    require Sympa::Spindle::ProcessArchive;
    my $m = Sympa::Message->new($plain, context => list());
    $m->{dkim2_headers} = "Message-Instance: m=1; h=sha256:x:y;\r\n\r\n";
    my $s = Sympa::Spindle::ProcessArchive::_custom_archiver_text($m);
    unlike $s, qr/X-Sympa-DKIM2-Headers/, 'not in archive copy';
    ok defined $m->{dkim2_headers}, 'delivered message keeps its saved headers';
    like $m->to_string, qr/^X-Sympa-DKIM2-Headers:/m, 'still spooled';
};

subtest 'X-DKIM2-Info above each instance Sympa adds' => sub {
    my $w = through($plain, sub { $_[0]->replace_header('Subject', '[test] hi') });
    like $w, qr/\AX-DKIM2-Info: (?:[^\r\n]|\r\n[ \t])*?action=mi-m=2;.*?\r\nMessage-Instance: m=2;/s, 'above m=2';
    like $w, qr/X-DKIM2-Info: (?:[^\r\n]|\r\n[ \t])*?action=mi-m=1;.*?\r\nMessage-Instance: m=1;/s, 'above m=1';
    my ($info) = $w =~ /\AX-DKIM2-Info: (.*?)\r\n(?![ \t])/s;
    $info =~ s/\r\n[ \t]+/ /g;
    like $info, qr/\A(?:[a-z0-9-]+=[^;]*; ?)+\z/, 'tag-list, every tag ends in ;';
    like $info, qr/draft=ietf-dkim-dkim2-spec-06;/, 'draft';
    like $info, qr/hc=\d+; hn=[a-z0-9,-]+;/, 'hashed header count and names';
};

# ---- Regression cases from the adversarial review (scratchpad exp/) ----

# The header block of a wire text, unfolded, plus every Recipe in it decoded:
# everything a recipient can read outside the body.
sub visible_headers { my $w = shift;
    my ($h) = split /\r\n\r\n/, $w, 2;
    $h =~ s/\r\n[ \t]+/ /g;
    my @r = map { (my $r = $_) =~ s/\s+//g; decode_base64($r) }
        $h =~ /^Message-Instance: [^\r\n]*?\br=([^;]+);/mg;
    return join "\n", $h, @r }
# The m=2 field of a wire text (folded, as sent).
sub top_field { ($_[0] =~ /^(Message-Instance: m=2;.*?)\r\n(?![ \t])/ms)[0] // '' }

my $rhdr = "From: Alice <a\@example.com>\nTo: test\@mail.example.org\nSubject: hello\nMessage-ID: <%s\@example.com>\nDate: Mon, 5 Oct 2026 10:00:00 +0000\nMIME-Version: 1.0\n";
sub rmsg { my ($id, $rest) = @_; sprintf($rhdr, $id) . $rest }

subtest 'review: real decorate cases' => sub {
    my $alt = "Content-Type: multipart/alternative; boundary=\"ALT\"\n\n--ALT\nContent-Type: text/plain; charset=us-ascii\n\nplain part\n--ALT\nContent-Type: text/html; charset=us-ascii\n\n<html><body><p>html part</p></body></html>\n--ALT--\n";
    my $mixed = "Content-Type: multipart/mixed; boundary=\"MIX\"\n\n--MIX\nContent-Type: text/plain; charset=us-ascii\n\nbody text\n--MIX\nContent-Type: application/pdf; name=\"a.pdf\"\nContent-Disposition: attachment; filename=\"a.pdf\"\nContent-Transfer-Encoding: base64\n\n" . encode_base64("PDFDATA" x 50) . "--MIX--\n";
    my $signed = "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"SIG\"\n\n--SIG\nContent-Type: text/plain; charset=us-ascii\n\nsigned text\n--SIG\nContent-Type: application/pgp-signature\n\n-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n--SIG--\n";
    my $foot = {message_footer => "-- \nfooter\n"};
    my @cases = (
        ['plain 7bit', rmsg('c1', "Content-Type: text/plain; charset=us-ascii\n\nhello\n"), $foot],
        ['no final newline', rmsg('c2', "Content-Type: text/plain; charset=us-ascii\n\nhello"), $foot],
        ['CRLF input', rmsg('c3', "Content-Type: text/plain; charset=us-ascii\n\nhello\n") =~ s/\n/\r\n/gr, $foot],
        (map { my $ft = $_;
            ["latin1 8bit, UTF-8 footer ($ft)", rmsg('c4', "Content-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\ncaf\xe9\n"),
             {message_footer => "-- \nfoot\xc3\xa9r \xe2\x82\xac\n"}, undef, footer_type => $ft] } qw(append mime)),
        ['multipart/alternative, mime footer', rmsg('c6', $alt), $foot],
        ['mixed with PDF', rmsg('c7', $mixed), $foot],
        ['PGP/MIME signed', rmsg('c8', $signed), $foot],
        ['html only', rmsg('c9', "Content-Type: text/html; charset=us-ascii\n\n<html><body>hi</body></html>\n"), $foot],
        ['header-only changes', rmsg('c10', "Content-Type: text/plain\n\nhello\n"), {}, sub {
            $_[0]->add_header('List-Id', '<test.mail.example.org>');
            $_[0]->replace_header('Subject', '[test] hello');
            $_[0]->replace_header('Reply-To', 'test@mail.example.org') }],
        ['empty body', rmsg('c11', "Content-Type: text/plain\n\n"), $foot],
        ['1200-char line', rmsg('c12', "Content-Type: text/plain\n\n" . ("X" x 1200) . "\n"), $foot],
        ['image only', rmsg('c13', "Content-Type: image/png\nContent-Transfer-Encoding: base64\n\n" . encode_base64("\x89PNG" . ("x" x 300))), $foot],
        ['odd folding', rmsg('c14', "X-Foo: a\nReferences: <a\@b>\n\t<c\@d>\n   <e\@f>\nContent-Type: text/plain\n\nhello\n"), $foot],
        ['Keywords:abc', rmsg('c15', "Keywords:abc\nContent-Type: text/plain\n\nhello\n"), $foot],
        ['Bcc', rmsg('c16', "Bcc: secret\@example.com\nContent-Type: text/plain\n\nhello\n"), {}],
        ['dot lines', rmsg('c17', "Content-Type: text/plain\n\n.\n..\nFrom me\n"), $foot],
        ['trailing blank lines', rmsg('c18', "Content-Type: text/plain\n\nhello\n\n\n\n"), $foot],
        ['bare CR', rmsg('c19', "Content-Type: text/plain\n\nhel\rlo\n"), $foot],
    );
    for my $c (@cases) {
        my ($name, $raw, $files, $mod, @listopts) = @$c;
        local %FILES;
        set_file($_, $files->{$_}) for keys %$files;
        my $w = through($raw, $mod, @listopts);
        chain_ok($w, $name);
        if (my $mi = top_recipe($w)) {
            ok !$mi->unrecoverable, "$name: body recoverable";
        }
    }
    local %FILES;
    set_file('message_footer', "-- \nfooter\n");
    my $w = through(rmsg('c20', "Content-Type: text/plain\n\nhello\n"), undef,
        footer_type => 'append');
    like $w, qr{^Content-Type: multipart/mixed}mi, 'footer_type append: wrapped';
    chain_ok($w, 'footer_type append');
};

# The review's QP and charset bugs were in append mode (stock in-place
# editing); with DKIM2 on, append and mime both wrap.
subtest 'review: QP post' => sub {
    my $raw = "From: a\@example.com\nTo: test\@mail.example.org\nSubject: qp\nMessage-ID: <qp1\@example.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\n"
        . "Caf=C3=A9 au lait, 1+1=3D2. This is a long line that goes past the soft br=\neak boundary so QP had to wrap it.\n";
    my $text = "Caf\xc3\xa9 au lait, 1+1=2. This is a long line that goes past the soft break boundary so QP had to wrap it.\n";
    local %FILES;
    set_file('message_footer', "-- \nList footer\n");
    for my $ft (qw(append mime)) {
        my ($w, $m) = through($raw, undef, footer_type => $ft);
        chain_ok($w, "$ft: verifies");
        like $w, qr{^Content-Type: multipart/mixed}mi, "$ft: wrapped";
        my ($first, $last) = @{$m->{_dkim2_body_lines}};
        my @lines = split /\r\n/, (split /\r\n\r\n/, $w, 2)[1], -1;
        (my $rcvd = (split /\n\n/, $raw, 2)[1]) =~ s/\n/\r\n/g;
        is join("\r\n", @lines[$first - 1 .. $last - 1]) . "\r\n", $rcvd,
            "$ft: original part is the received body, byte for byte";
        my @p = $m->as_entity->parts;
        is $p[0]->bodyhandle->as_string, $text, "$ft: original part decodes once";
        is $p[-1]->bodyhandle->as_string, "-- \nList footer\n",
            "$ft: footer part decodes to the footer";
    }
    # Switch off, append: stock edits the body in place, which was correct.
    my ($w, $m) = through($raw, undef, footer_type => 'append',
        dkim2_message_instance => 'off');
    unlike $w, qr/^Message-Instance:/m, 'off: no instance';
    my $dec = $m->as_entity->bodyhandle->as_string;
    unlike $dec, qr/=C3=A9|=3D/, 'off append: decoded once';
    like $dec, qr/\A\Q$text\E.*-- \nList footer\n\z/s,
        'off append: original text, then the footer';
};

subtest 'review: non-ASCII footer on a us-ascii post' => sub {
    my $raw = "From: a\@example.com\nTo: test\@mail.example.org\nSubject: as\nMessage-ID: <as\@x>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=us-ascii\n\nplain ascii\n";
    my $footer = "Euro \xe2\x82\xac, \xe6\x97\xa5\xe6\x9c\xac\n";
    local %FILES;
    set_file('message_footer', $footer);
    for my $ft (qw(append mime)) {
        my ($w, $m) = through($raw, undef, footer_type => $ft);
        chain_ok($w, "$ft: verifies");
        my @p = $m->as_entity->parts;
        is $p[0]->bodyhandle->as_string, "plain ascii\n", "$ft: original part";
        like $p[0]->head->get('Content-Type'), qr/charset=us-ascii/i,
            "$ft: original part keeps us-ascii";
        like $p[-1]->head->get('Content-Type'), qr/charset="?UTF-8"?/i,
            "$ft: footer part charset=UTF-8";
        is $p[-1]->bodyhandle->as_string, $footer, "$ft: footer bytes intact";
        unlike $w, qr/Euro \?/, "$ft: no ? substitution";
    }
};

subtest 'review: S/MIME encryption after decorate -> null, no plaintext in headers' => sub {
    my $raw = "From: a\@example.com\nTo: test\@mail.example.org\nSubject: secret\nMessage-ID: <s\@x>\nMIME-Version: 1.0\nContent-Type: text/plain\n\nThe merger closes on Friday; password is hunter2.\n";
    my $l = list();
    my $m = Sympa::Message->new($raw, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l);
    my $ctx = Sympa::DKIM2::egress_context($b);
    my ($stored, $err);
    {
        # Stand-in for smime_encrypt(): an opaque blob replaces the body.
        no warnings qw(redefine once);
        local *Sympa::Message::smime_encrypt = sub {
            my $self = shift;
            $self->replace_header('Content-Type',
                'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m');
            $self->replace_header('Content-Transfer-Encoding', 'base64');
            $self->{_body} = encode_base64(join '', map { chr(($_ * 37) % 256) } 1 .. 600);
            delete $self->{_entity_cache};
            1;
        };
        local *STDERR; open STDERR, '>', \$err or die;
        ($stored) = twist_one($b, $ctx, smime_encrypt => 1);
    }
    my $w = $stored->[0]->as_rfc822_string;
    like $w, qr{^Content-Type: application/pkcs7-mime}m, 'encrypted';
    ok top_recipe($w)->unrecoverable, 'b null';
    unlike $err // '', qr/changed after ingress/, 'body_rewritten passed (no fallback notice)';
    unlike visible_headers($w), qr/hunter2|merger/, 'plaintext in no header or Recipe';
    chain_ok($w, 'header history verifies');
};

subtest 'review: moderation round trip' => sub {
    my $raw = "From: a\@example.com\nTo: test\@mail.example.org\nSubject: mod\nMessage-ID: <mod\@x>\nMIME-Version: 1.0\nContent-Type: text/plain\n\nplease moderate\n";
    local %FILES;
    set_file('message_footer', "-- \nfooter\n");
    my $l = list();
    my $m = Sympa::Message->new($raw, context => $l);
    Sympa::DKIM2::ingress($m);
    $m->replace_header('Subject', '[test] mod');                    # custom_subject
    my $mod = Sympa::Message->new($m->to_string(original => 1), context => $l);  # ToModeration
    ok defined $mod->{dkim2_headers}, 'saved headers survive the moderation spool';
    my $b = Sympa::Message->new($mod->to_string, context => $l);     # bulk spool
    my $ctx = Sympa::DKIM2::egress_context($b);
    my $one = $b->dup;
    $one->decorate($l, undef);
    Sympa::DKIM2::egress_add($one, $ctx);
    my $w = $one->as_rfc822_string;
    my $mi = top_recipe($w);
    ok $mi && !$mi->unrecoverable, 'm=2, body recoverable';
    chain_ok($w, 'verifies');
};

subtest 'review: notice mode -> null, small instance' => sub {
    my $att = encode_base64(join '', map { chr(($_ * 7919) % 256) } 1 .. 300000);
    my $raw = "From: a\@example.com\nTo: test\@mail.example.org\nSubject: big\nMessage-ID: <big\@x>\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/plain\n\nsee attached\n--B\nContent-Type: application/octet-stream; name=a.bin\nContent-Disposition: attachment; filename=a.bin\nContent-Transfer-Encoding: base64\n\n$att--B--\n";
    my $w = through($raw, undef,
        pre => sub { $_[0]->prepare_message_according_to_mode('notice', $_[1]) },
        decorate => 0);
    ok top_recipe($w)->unrecoverable, 'b null';
    cmp_ok length(top_field($w)), '<', 4096, 'Message-Instance under 4 KB';
    chain_ok($w, 'verifies');
};

subtest 'review: txt mode -> null, small instance' => sub {
    my $txt  = join '', map { "line $_ with caf\xc3\xa9 text\n" } 1 .. 40;
    my $html = "<html><body>" . join('', map { "<p>para $_ caf&eacute;</p>\n" } 1 .. 200) . "</body></html>\n";
    my $raw = "From: a\@example.com\nTo: test\@mail.example.org\nSubject: alt\nMessage-ID: <alt\@x>\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=ALT\n\n--ALT\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n"
        . encode_base64($txt) . "--ALT\nContent-Type: text/html; charset=utf-8\n\n$html--ALT--\n";
    local %FILES;
    set_file('message_footer', "-- \nfooter\n");
    my ($w, $err) = ('', '');
    {
        local *STDERR; open STDERR, '>', \$err or die;
        $w = through($raw, undef,
            pre => sub { $_[0]->prepare_message_according_to_mode('txt', $_[1]) });
    }
    is join('', map {"$_\n"} grep { !/^notice .*Multipart message changed to singlepart/ }
        split /\n/, $err), '', 'only the singlepart notice logged';
    unlike $w, qr/^Content-Type: multipart\/alternative/mi, 'single part';
    ok top_recipe($w)->unrecoverable, 'b null';
    cmp_ok length(top_field($w)), '<', 4096, 'Message-Instance under 4 KB';
    chain_ok($w, 'verifies');
};

subtest 'review: MDN header set after decorate' => sub {
    local %FILES;
    set_file('message_footer', "-- \nfooter\n");
    my $w = through($plain, sub { $_[0]->add_header('List-Id', '<t>') },
        post => sub { $_[0]->replace_header('Disposition-Notification-To',
                          'test-owner+abc@mail.example.org') });
    like $w, qr/^Disposition-Notification-To: test-owner\+abc\@/m, 'MDN header';
    ok top_recipe($w)->get_tag('rh')->{'disposition-notification-to'},
        'in the header Recipe';
    chain_ok($w, 'verifies');
};

subtest 'review: footer personalised per recipient' => sub {
    local %FILES;
    set_file('message_footer', "for [% user.email %]\n");
    no warnings qw(redefine once);
    local *Sympa::List::get_list_member =
        sub { +{email => $_[1], date => 0} };
    my $l = list();
    my $m = Sympa::Message->new($plain, context => $l);
    Sympa::DKIM2::ingress($m);
    my $b = Sympa::Message->new($m->to_string, context => $l);
    my $ctx = Sympa::DKIM2::egress_context($b);
    my (@w, @lines);
    for my $rcpt (map {"r$_\@example.net"} 1 .. 3) {
        my $one = $b->dup;
        $one->decorate($l, $rcpt, mode => 'footer');
        Sympa::DKIM2::egress_add($one, $ctx);
        push @w, $one->as_rfc822_string;
        push @lines, $one->{_dkim2_body_lines};
        like $w[-1], qr/^for \Q$rcpt\E\r$/m, "$rcpt: personalised";
        chain_ok($w[-1], "$rcpt: verifies");
    }
    is_deeply $lines[$_], $lines[0], "copy range $_ same as 0" for 1, 2;
    my $last = $lines[0][1];
    my @body = map { my @l = split /\r\n/, (split /\r\n\r\n/, $_, 2)[1], -1; \@l } @w;
    # The boundary is random per copy: compare with it masked.
    my @masked = map { [map { s/=_dkim2_[0-9a-f]+/BOUNDARY/gr } @$_] } @body;
    for my $i (1, 2) {
        my ($d) = grep { $masked[0][$_] ne ($masked[$i][$_] // '') } 0 .. $#{$masked[0]};
        ok defined $d && $d + 1 > $last,
            "copy $i differs from copy 0, only after line $last"
            or diag defined $d ? "first difference at line " . ($d + 1) : 'copies identical';
    }
};

subtest 'review: upstream m=1 kept' => sub {
    my $hdr = "From: Alice <a\@example.com>\nTo: test\@mail.example.org\nSubject: hello\nMessage-ID: <%s\@example.com>\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n";
    my $longref = join ' ', map {"<msg$_\@example.com>"} 1 .. 80;
    local %FILES;
    set_file('message_footer', "-- \nfooter\n");
    for my $c (
        ['simple', sprintf($hdr, 'u1') . "\nhello\n"],
        ['long unfolded References', sprintf($hdr, 'u2') . "References: $longref\n\nhello\n"],
        ['8bit UTF-8 Subject', sprintf($hdr, 'u3') =~ s/Subject: hello/Subject: h\xc3\xa9llo/r . "\nhello\n"],
        ['empty header value', sprintf($hdr, 'u4') . "Keywords:\n\nhello\n"],
        ['trailing space', sprintf($hdr, 'u5') . "X-A: 1\nComments: hi   \n\nhello\n"],
    ) {
        my ($name, $raw) = @$c;
        (my $crlf = $raw) =~ s/\n/\r\n/g;
        my $up = Mail::DKIM2::MessageInstance->calculate($crlf)->as_string;
        my $w = through("Message-Instance: $up\n$raw");
        my @m1 = map { s/\r\n[ \t]+/ /gr } $w =~ /^Message-Instance: (m=1;.*?)\r\n(?![ \t])/msg;
        is scalar(@m1), 1, "$name: one m=1";
        is $m1[0] =~ s/\s+//gr, $up =~ s/\s+//gr, "$name: upstream m=1 kept";
        unlike $w, qr/action=mi-m=1;/, "$name: Sympa added no m=1";
        my $mi = top_recipe($w);
        ok $mi && !$mi->unrecoverable, "$name: m=2, body recoverable";
        chain_ok($w, "$name: verifies");
    }
};

done_testing;
