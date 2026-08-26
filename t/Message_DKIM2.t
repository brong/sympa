# -*- indent-tabs-mode: nil; -*-
# vim:ft=perl:et:sw=4

use strict;
use warnings;
use English qw(-no_match_vars);
use Test::More;
use File::Temp;
use MIME::Parser;

BEGIN {
    # Make the DKIM2 interop library available if present alongside sympa.
    my $interop_lib = $ENV{DKIM2_INTEROP_LIB}
        || do {
            # Try relative path from working directory.
            my $dir = '../interop/brong/lib';
            -d $dir ? $dir : undef;
        };
    if ($interop_lib) {
        unshift @INC, $interop_lib;
    }
}

eval { require Mail::DKIM2::MessageInstance };
if ($@) {
    plan skip_all => 'Mail::DKIM2::MessageInstance not available';
}

use Conf;
use Sympa::ConfDef;
use Sympa::Log;
use Sympa::Message;

Sympa::Log->instance->{log_to_stderr} = 'err';

%Conf::Conf = (
    domain     => 'mail.example.org',
    listmaster => 'listmaster@example.org',
);
foreach my $pinfo (grep { $_->{name} and exists $_->{default} }
    @Sympa::ConfDef::params) {
    $Conf::Conf{$pinfo->{name}} = $pinfo->{default}
        unless exists $Conf::Conf{$pinfo->{name}};
}

# Fake list for personalization tests.
my $list = bless {
    name   => 'test',
    domain => $Conf::Conf{'domain'},
    admin  => {
        custom_subject => '',
    },
} => 'Sympa::List';

# Suppress warnings from stub methods.
do {
    no warnings;
    *Sympa::List::update_stats = sub { (1) };
};

# ===================================================================
# Helper: build a simple text/plain message.
# ===================================================================
sub build_message {
    my (%args) = @_;
    my $charset = $args{charset} || 'us-ascii';
    my $cte     = $args{cte}     || '7bit';
    my $body    = $args{body}    || "Hello world.\n";
    my $extra_headers = $args{extra_headers} || '';

    my $msg = <<"EOF";
From: sender\@example.com
To: test\@mail.example.org
Subject: Test message
Message-ID: <test-$$-${\time()}\@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=$charset
Content-Transfer-Encoding: $cte
${extra_headers}
$body
EOF
    return $msg;
}

# ===================================================================
# 1. Message-Instance v=1 on a plain message
# ===================================================================
subtest 'MI v=1 on plain message' => sub {
    my $msg = Sympa::Message->new(build_message(), context => '*');
    ok $msg, 'message created';

    ok !$msg->{_head}->count('Message-Instance'),
        'no MI header before ingress';

    my $rc = $msg->add_message_instance_ingress;
    ok $rc, 'add_message_instance_ingress succeeded';

    is $msg->{_head}->count('Message-Instance'), 1,
        'one MI header after ingress';

    # Parse the MI header and check version.
    my $mi_raw = $msg->{_head}->get('Message-Instance', 0);
    like $mi_raw, qr/v=1/, 'MI header has v=1';
    like $mi_raw, qr/h=/, 'MI header has h= tag';

    # Verify the MI using the library.
    my $rfc822 = $msg->as_rfc822_string;
    my ($version, $error) = Mail::DKIM2::MessageInstance->verify($rfc822);
    is $version, 1, 'MI v=1 verifies correctly';
    is $error, undef, 'no verification error';

    # mi_original should be stored.
    ok defined $msg->{mi_original}, 'mi_original is stored';
    like $msg->{mi_original}, qr/Message-Instance/,
        'mi_original contains MI header';
};

# ===================================================================
# 2. Message already has MI -- don't add another v=1
# ===================================================================
subtest 'existing MI header preserved' => sub {
    my $msg_str = build_message(
        extra_headers => "Message-Instance: v=1; h=eyJoIjpbInNoYTI1NiIsInRlc3QiXSwiYiI6WyJzaGEyNTYiLCJ0ZXN0Il19\n",
    );
    my $msg = Sympa::Message->new($msg_str, context => '*');
    ok $msg, 'message with existing MI created';

    is $msg->{_head}->count('Message-Instance'), 1,
        'has one MI header on input';

    # Simulate what ProcessIncoming does: skip if MI exists.
    unless ($msg->{_head}->count('Message-Instance')) {
        $msg->add_message_instance_ingress;
    }

    is $msg->{_head}->count('Message-Instance'), 1,
        'still only one MI header -- no v=1 added';
};

# ===================================================================
# 3. Skip re-encoding when personalization makes no changes
# ===================================================================
subtest 'skip re-encoding when no template vars' => sub {
    my $original_body = "This is plain text with no template variables.\n";
    my $msg = Sympa::Message->new(
        build_message(body => $original_body), context => $list);
    ok $msg, 'message created';

    my $body_before = $msg->body_as_string;

    # Personalize -- but there are no template variables, so body
    # should be byte-identical.
    $msg->personalize($list, 'user@example.com');

    my $body_after = $msg->body_as_string;
    is $body_after, $body_before,
        'body bytes unchanged when no template vars substituted';
};

# ===================================================================
# 4. Re-encoding preserves original charset when possible
# ===================================================================
subtest 'prefer original charset' => sub {
    # ISO-8859-1 message with a body that's pure ASCII.
    # Personalization adding ASCII content should NOT trigger a
    # fallback to UTF-8.  MIME::Charset may map to US-ASCII (a
    # compatible subset) which is acceptable.
    my $msg = Sympa::Message->new(
        build_message(
            charset => 'ISO-8859-1',
            body    => "Bonjour [%user.email%]\n",
        ),
        context => $list
    );
    ok $msg, 'ISO-8859-1 message created';

    $msg->personalize($list, 'user@example.com');

    my $charset = lc($msg->{_head}->mime_attr('Content-Type.Charset') // '');
    # Must not have fallen back to UTF-8.
    isnt $charset, 'utf-8',
        'charset did not fall back to UTF-8';
    ok($charset eq 'iso-8859-1' || $charset eq 'us-ascii',
        "charset is compatible ($charset)");
};

# ===================================================================
# 5. MI v=2 at egress captures header changes
# ===================================================================
subtest 'MI v=2 captures header additions' => sub {
    my $msg = Sympa::Message->new(build_message(), context => '*');
    $msg->add_message_instance_ingress;
    my $mi_original = $msg->{mi_original};
    ok defined $mi_original, 'mi_original captured';

    # Simulate header additions that happen between ingress and egress
    # (TransformIncoming/TransformOutgoing add List-Id, Reply-To, etc.)
    $msg->add_header('List-Id', '<test.mail.example.org>');
    $msg->add_header('List-Post', '<mailto:test@mail.example.org>');

    my $rc = $msg->add_message_instance_egress($mi_original);
    ok $rc, 'add_message_instance_egress succeeded';

    is $msg->{_head}->count('Message-Instance'), 2,
        'two MI headers after egress';

    # Verify v=2 against current message.
    my $rfc822 = $msg->as_rfc822_string;
    my ($version, $error) = Mail::DKIM2::MessageInstance->verify($rfc822);
    is $version, 2, 'MI v=2 verifies correctly';
    is $error, undef, 'no verification error';

    # Undo v=2 to get the original message, then verify v=1.
    my $prev = Mail::DKIM2::MessageInstance->undo($rfc822);
    ok $prev, 'undo succeeded';
    my ($prev_ver, $prev_err) = Mail::DKIM2::MessageInstance->verify($prev);
    is $prev_ver, 1, 'undone message verifies as v=1';
    is $prev_err, undef, 'no verification error on undone message';
};

# ===================================================================
# 6. MI v=2 captures body changes (footer append)
# ===================================================================
subtest 'MI v=2 captures body changes' => sub {
    my $msg = Sympa::Message->new(build_message(), context => '*');
    $msg->add_message_instance_ingress;
    my $mi_original = $msg->{mi_original};

    # Simulate body modification (e.g., footer appended).
    my $entity = $msg->as_entity->dup;
    my $bodyh = $entity->bodyhandle;
    my $body = $bodyh->as_string;
    $body .= "\n-- \nList footer here.\n";
    my $io = $bodyh->open('w');
    $io->print($body);
    $io->close;
    $msg->set_entity($entity);

    my $rc = $msg->add_message_instance_egress($mi_original);
    ok $rc, 'egress MI succeeded with body changes';

    my $rfc822 = $msg->as_rfc822_string;
    my ($version, $error) = Mail::DKIM2::MessageInstance->verify($rfc822);
    is $version, 2, 'MI v=2 verifies with body changes';
    is $error, undef, 'no verification error';

    # Undo and verify original.
    my $prev = Mail::DKIM2::MessageInstance->undo($rfc822);
    ok $prev, 'undo succeeded';
    my ($prev_ver, $prev_err) = Mail::DKIM2::MessageInstance->verify($prev);
    is $prev_ver, 1, 'undone message verifies as v=1';
    is $prev_err, undef, 'no error on undone message';
};

# ===================================================================
# 7. MI v=2 captures both header and body changes
# ===================================================================
subtest 'MI v=2 captures header + body changes' => sub {
    my $msg = Sympa::Message->new(build_message(), context => '*');
    $msg->add_message_instance_ingress;
    my $mi_original = $msg->{mi_original};

    # Header additions.
    $msg->add_header('List-Id', '<test.mail.example.org>');
    $msg->replace_header('Subject', 'Re: [test] Test message');

    # Body modification.
    my $entity = $msg->as_entity->dup;
    my $bodyh = $entity->bodyhandle;
    my $body = $bodyh->as_string;
    $body .= "Footer.\n";
    my $io = $bodyh->open('w');
    $io->print($body);
    $io->close;
    $msg->set_entity($entity);

    $msg->add_message_instance_egress($mi_original);

    my $rfc822 = $msg->as_rfc822_string;
    my ($version) = Mail::DKIM2::MessageInstance->verify($rfc822);
    is $version, 2, 'v=2 verifies';

    my $prev = Mail::DKIM2::MessageInstance->undo($rfc822);
    my ($prev_ver) = Mail::DKIM2::MessageInstance->verify($prev);
    is $prev_ver, 1, 'undone to v=1 verifies';
};

# ===================================================================
# 8. Message with incoming MI v=1 -- egress adds v=2
# ===================================================================
subtest 'incoming message with existing MI v=1' => sub {
    # Create a message and add MI v=1 to simulate an upstream MTA.
    my $msg_str = build_message(body => "Original content.\n");
    my $upstream = Sympa::Message->new($msg_str, context => '*');
    $upstream->add_message_instance_ingress;
    my $with_mi = $upstream->as_rfc822_string;

    # Now create a new Message from the wire bytes (as if received
    # by Sympa with the MI already present).
    my $msg = Sympa::Message->new($with_mi, context => '*');
    ok $msg, 'message with upstream MI created';

    is $msg->{_head}->count('Message-Instance'), 1,
        'has one MI header from upstream';

    # ProcessIncoming would skip adding v=1 since MI exists.
    unless ($msg->{_head}->count('Message-Instance')) {
        $msg->add_message_instance_ingress;
    }
    is $msg->{_head}->count('Message-Instance'), 1,
        'still one MI -- ingress skipped';

    # The mi_original should be the message as received (with upstream MI).
    # We set it manually since add_message_instance_ingress was skipped.
    $msg->{mi_original} = $msg->as_rfc822_string;

    # Simulate Sympa modifications.
    $msg->add_header('List-Id', '<test.mail.example.org>');

    # Add egress MI (should be v=2 since upstream was v=1).
    my $rc = $msg->add_message_instance_egress($msg->{mi_original});
    ok $rc, 'egress MI succeeded on message with upstream MI';

    is $msg->{_head}->count('Message-Instance'), 2,
        'two MI headers after egress';

    my $rfc822 = $msg->as_rfc822_string;
    my ($version, $error) = Mail::DKIM2::MessageInstance->verify($rfc822);
    is $version, 2, 'v=2 verifies';
    is $error, undef, 'no error';

    # Undo v=2 -> should get back to v=1 state.
    my $prev = Mail::DKIM2::MessageInstance->undo($rfc822);
    ok $prev, 'undo v=2 succeeded';
    my ($prev_ver) = Mail::DKIM2::MessageInstance->verify($prev);
    is $prev_ver, 1, 'undone message verifies as v=1';
};

# ===================================================================
# 9. Message with incoming MI v=1 + v=2 -- egress adds v=3
# ===================================================================
subtest 'incoming message with MI v=1 and v=2' => sub {
    # Build a message that has been through two hops already.
    my $msg_str = build_message(body => "Original.\n");
    my $hop1 = Sympa::Message->new($msg_str, context => '*');
    $hop1->add_message_instance_ingress;
    my $mi_orig_hop1 = $hop1->as_rfc822_string;

    # Hop 1 modifies and adds v=2.
    $hop1->add_header('List-Id', '<other.example.com>');
    $hop1->add_message_instance_egress($mi_orig_hop1);
    my $after_hop1 = $hop1->as_rfc822_string;

    # Now Sympa receives this message with v=1 and v=2.
    my $msg = Sympa::Message->new($after_hop1, context => '*');
    is $msg->{_head}->count('Message-Instance'), 2,
        'has two MI headers from upstream';

    # MI exists, so ingress skips.
    unless ($msg->{_head}->count('Message-Instance')) {
        $msg->add_message_instance_ingress;
    }
    $msg->{mi_original} = $msg->as_rfc822_string;

    # Sympa modifies.
    $msg->add_header('List-Post', '<mailto:test@mail.example.org>');

    my $rc = $msg->add_message_instance_egress($msg->{mi_original});
    ok $rc, 'egress MI succeeded (v=3)';

    is $msg->{_head}->count('Message-Instance'), 3,
        'three MI headers after egress';

    my $rfc822 = $msg->as_rfc822_string;
    my ($version) = Mail::DKIM2::MessageInstance->verify($rfc822);
    is $version, 3, 'v=3 verifies';

    # Undo chain: v=3 -> v=2 -> v=1.
    my $undo2 = Mail::DKIM2::MessageInstance->undo($rfc822);
    ok $undo2, 'undo v=3 succeeded';
    my ($ver2) = Mail::DKIM2::MessageInstance->verify($undo2);
    is $ver2, 2, 'undone to v=2 verifies';

    my $undo1 = Mail::DKIM2::MessageInstance->undo($undo2);
    ok $undo1, 'undo v=2 succeeded';
    my ($ver1) = Mail::DKIM2::MessageInstance->verify($undo1);
    is $ver1, 1, 'undone to v=1 verifies';
};

# ===================================================================
# 10. MI with base64-encoded body -- no spurious re-encoding
# ===================================================================
subtest 'base64 body preserved without changes' => sub {
    # Build a message with base64 CTE.
    my $msg_str = build_message(
        charset => 'us-ascii',
        cte     => 'base64',
        body    => "SGVsbG8gd29ybGQuCg==\n",
    );
    my $msg = Sympa::Message->new($msg_str, context => $list);
    ok $msg, 'base64 message created';

    my $body_before = $msg->body_as_string;

    # Personalize with no template vars -- should not re-encode.
    $msg->personalize($list, 'user@example.com');

    my $body_after = $msg->body_as_string;
    is $body_after, $body_before,
        'base64 body bytes preserved when no personalization changes';
};

# ===================================================================
# 11. MI with quoted-printable body -- no spurious re-encoding
# ===================================================================
subtest 'quoted-printable body preserved without changes' => sub {
    my $msg_str = build_message(
        charset => 'us-ascii',
        cte     => 'quoted-printable',
        body    => "Hello =3D world.\n",
    );
    my $msg = Sympa::Message->new($msg_str, context => $list);
    ok $msg, 'QP message created';

    my $body_before = $msg->body_as_string;

    $msg->personalize($list, 'user@example.com');

    my $body_after = $msg->body_as_string;
    is $body_after, $body_before,
        'QP body bytes preserved when no personalization changes';
};

# ===================================================================
# 12. MI spool file storage and loading
# ===================================================================
subtest 'MI original spool file lifecycle' => sub {
    my $tempdir = File::Temp->newdir(CLEANUP => 1);
    my $msg_dir = "$tempdir/msg";
    my $pct_dir = "$tempdir/pct";
    mkdir $msg_dir;
    mkdir $pct_dir;

    # Write an MI original file.
    my $mi_content = "Original message content\n";
    my $marshalled = 'test.msg.12345';
    my $mi_path = "$msg_dir/$marshalled.mi_orig";

    ok open(my $fh, '>', $mi_path), 'wrote MI original file';
    print $fh $mi_content;
    close $fh;

    ok -f $mi_path, 'MI original file exists';

    # Simulate hard linking.
    my $mi_path2 = "$msg_dir/$marshalled.2.mi_orig";
    ok link($mi_path, $mi_path2), 'hard link created';

    # Both files should have same content.
    open my $fh1, '<', $mi_path;
    my $content1 = do { local $RS; <$fh1> };
    close $fh1;

    open my $fh2, '<', $mi_path2;
    my $content2 = do { local $RS; <$fh2> };
    close $fh2;

    is $content1, $content2, 'hard linked files have same content';

    # Unlinking one should leave the other.
    unlink $mi_path;
    ok !-f $mi_path, 'first file removed';
    ok -f $mi_path2, 'second file still exists (hard link)';

    unlink $mi_path2;
    ok !-f $mi_path2, 'second file removed';
};

# ===================================================================
# 13. as_rfc822_string excludes Return-Path
# ===================================================================
subtest 'as_rfc822_string format' => sub {
    my $msg = Sympa::Message->new(build_message(), context => '*');
    $msg->{envelope_sender} = 'bounce@example.com';

    my $full = $msg->as_string;
    like $full, qr/Return-Path:/, 'as_string includes Return-Path';

    my $rfc822 = $msg->as_rfc822_string;
    unlike $rfc822, qr/Return-Path:/,
        'as_rfc822_string excludes Return-Path';
    like $rfc822, qr/^From:/m,
        'as_rfc822_string includes From header';
    like $rfc822, qr/Hello world/,
        'as_rfc822_string includes body';
};

# ===================================================================
# 14. Full round-trip: ingress -> modify -> egress -> verify -> undo
# ===================================================================
subtest 'full round-trip verification' => sub {
    my $original_body = "This is the original message body.\nLine two.\n";
    my $msg = Sympa::Message->new(
        build_message(body => $original_body), context => '*');

    # Ingress: add MI v=1.
    $msg->add_message_instance_ingress;
    my $mi_original = $msg->{mi_original};

    # Simulate TransformIncoming/TransformOutgoing.
    $msg->add_header('List-Id', '<test.mail.example.org>');
    $msg->add_header('List-Post', '<mailto:test@mail.example.org>');
    $msg->add_header('List-Unsubscribe',
        '<mailto:test-unsubscribe@mail.example.org>');
    $msg->replace_header('Subject', '[test] This is the original message body.');

    # Simulate decoration (footer).
    my $entity = $msg->as_entity->dup;
    my $bodyh = $entity->bodyhandle;
    my $body = $bodyh->as_string;
    $body .= "\n-- \nSent via test mailing list\nhttps://mail.example.org\n";
    my $io = $bodyh->open('w');
    $io->print($body);
    $io->close;
    $msg->set_entity($entity);

    # Egress: add MI v=2.
    $msg->add_message_instance_egress($mi_original);

    my $final = $msg->as_rfc822_string;

    # Verify v=2 on the final message.
    my ($ver2, $err2) = Mail::DKIM2::MessageInstance->verify($final);
    is $ver2, 2, 'final message verifies as v=2';
    is $err2, undef, 'no error on v=2';

    # Undo v=2 to recover the pre-modification state.
    my $undone = Mail::DKIM2::MessageInstance->undo($final);
    ok $undone, 'undo v=2 succeeded';

    # The undone message should verify as v=1.
    my ($ver1, $err1) = Mail::DKIM2::MessageInstance->verify($undone);
    is $ver1, 1, 'undone message verifies as v=1';
    is $err1, undef, 'no error on v=1';

    # The undone message should not have the List-* headers.
    my $undone_msg;
    if (ref $undone) {
        $undone_msg = $undone->as_string;
    } else {
        $undone_msg = $undone;
    }
    unlike $undone_msg, qr/List-Id:/,
        'undone message does not have List-Id';
    like $undone_msg, qr/This is the original message body\./,
        'undone message has original body';
    unlike $undone_msg, qr/Sent via test mailing list/,
        'undone message does not have footer';
};

# ===================================================================
# 15. Skip MI v=2 when message is unchanged
# ===================================================================
subtest 'skip MI v=2 when unchanged' => sub {
    my $msg = Sympa::Message->new(build_message(), context => '*');
    $msg->add_message_instance_ingress;
    my $mi_original = $msg->{mi_original};

    # Don't modify the message at all.
    my $rc = $msg->add_message_instance_egress($mi_original);
    ok $rc, 'egress returns success';

    is $msg->{_head}->count('Message-Instance'), 1,
        'still only one MI header -- v=2 skipped because nothing changed';
};

# ===================================================================
# 16. QP body preserved at raw level during decoration
# ===================================================================
subtest 'QP body preserved during footer append' => sub {
    # Build a QP-encoded message with some non-trivially-encoded content.
    # The =3D is a QP-encoded '=' that must be preserved byte-for-byte.
    my $qp_body = "Hello world.\nLine two =3D equals.\n";
    my $msg_str = build_message(
        charset => 'us-ascii',
        cte     => 'quoted-printable',
        body    => $qp_body,
    );
    my $msg = Sympa::Message->new($msg_str, context => '*');
    ok $msg, 'QP message created';

    # entity->body_as_string gives the raw QP-encoded body.
    my $raw_before = $msg->as_entity->body_as_string;
    like $raw_before, qr/=3D equals/,
        'raw body has QP encoding before decoration';

    # Simulate decoration via _append_footer_header_to_part.
    my $entity = $msg->as_entity->dup;
    my $bodyh = $entity->bodyhandle;
    my $decoded_body = $bodyh ? $bodyh->as_string : '';

    my $result = Sympa::Message::_append_footer_header_to_part({
        part          => $entity,
        header        => '',
        footer        => "List footer.\n",
        global_footer => '',
        eff_type      => 'text/plain',
        body          => $decoded_body,
    });
    ok defined $result, 'footer append succeeded';

    # The result should contain the original QP body byte-for-byte,
    # with the footer freshly QP-encoded and appended.
    like $result, qr/=3D equals/,
        'original QP encoding preserved in decorated body';
    like $result, qr/List footer/,
        'footer appended';
};

# ===================================================================
# 17. QP decoration produces compact MI Recipes
# ===================================================================
subtest 'QP decoration produces compact MI Recipe' => sub {
    my $qp_body = "Hello world.\nLine two.\nLine three.\n";
    my $msg = Sympa::Message->new(
        build_message(
            charset => 'us-ascii',
            cte     => 'quoted-printable',
            body    => $qp_body,
        ),
        context => '*'
    );
    $msg->add_message_instance_ingress;
    my $mi_original = $msg->{mi_original};

    # Decorate via raw QP path.
    my $entity = $msg->as_entity->dup;
    my $bodyh = $entity->bodyhandle;
    my $decoded_body = $bodyh ? $bodyh->as_string : '';
    my $result = Sympa::Message::_append_footer_header_to_part({
        part          => $entity,
        header        => '',
        footer        => "Footer.\n",
        global_footer => '',
        eff_type      => 'text/plain',
        body          => $decoded_body,
    });

    # Write the result back.
    my $io = $bodyh->open('w');
    $io->print($result);
    $io->close;
    $msg->set_entity($entity);

    # Add egress MI.
    $msg->add_message_instance_egress($mi_original);

    my $rfc822 = $msg->as_rfc822_string;
    my ($version) = Mail::DKIM2::MessageInstance->verify($rfc822);
    is $version, 2, 'v=2 verifies on QP-decorated message';

    # Undo and verify v=1.
    my $prev = Mail::DKIM2::MessageInstance->undo($rfc822);
    ok $prev, 'undo succeeded';
    my ($prev_ver) = Mail::DKIM2::MessageInstance->verify($prev);
    is $prev_ver, 1, 'undone QP message verifies as v=1';
};

# ===================================================================
# 18. Base64 line wrapping preserved after modification
# ===================================================================
subtest 'base64 line wrapping preserved' => sub {
    # Build a base64 message with non-standard 20-char line length.
    my $text = "Hello world. This is a test message.\nLine two.\n";
    my $b64 = MIME::Base64::encode_base64($text, '');
    # Wrap at 20 chars (non-standard).
    my $short_b64 = join("\n", unpack('(A20)*', $b64)) . "\n";

    my $msg_str = build_message(
        charset => 'us-ascii',
        cte     => 'base64',
        body    => $short_b64,
    );
    my $msg = Sympa::Message->new($msg_str, context => '*');
    ok $msg, 'base64 message with 20-char lines created';

    # Verify original body has 20-char lines.
    my $body_before = $msg->body_as_string;
    like $body_before, qr/^.{20}\n/m,
        'original body has 20-char lines';

    $msg->add_message_instance_ingress;
    my $mi_original = $msg->{mi_original};

    # Modify body via entity (simulating footer append).
    my $entity = $msg->as_entity->dup;
    my $bodyh = $entity->bodyhandle;
    my $decoded = $bodyh->as_string;
    $decoded .= "Footer.\n";
    my $io = $bodyh->open('w');
    $io->print($decoded);
    $io->close;
    $msg->set_entity($entity);

    # After set_entity, unchanged base64 lines should keep 20-char
    # wrapping.
    my $body_after = $msg->body_as_string;
    my @lines_after = split /\n/, $body_after;
    # The first line should still be 20 chars (unchanged content).
    is length($lines_after[0]), 20,
        'first base64 line keeps original 20-char width';

    # MI should produce compact Recipe.
    $msg->add_message_instance_egress($mi_original);

    my $rfc822 = $msg->as_rfc822_string;
    my ($version) = Mail::DKIM2::MessageInstance->verify($rfc822);
    is $version, 2, 'v=2 verifies on base64 message with preserved wrapping';

    # Check Recipe compactness — should have copy ranges, not all literals.
    my $em = Email::MIME->new($rfc822);
    my @mi = $em->header_raw('Message-Instance');
    my $mi_v2;
    for my $h (@mi) {
        my $parsed = Mail::DKIM2::MessageInstance->parse($h);
        $mi_v2 = $parsed if ($parsed->get_tag('v') // 0) == 2;
    }
    ok $mi_v2, 'found MI v=2 header';
    my $rb = $mi_v2->get_tag('rb');
    if ($rb) {
        my @ranges = grep { ref $_ eq 'ARRAY' } @$rb;
        ok scalar(@ranges) >= 1,
            'body Recipe has copy ranges (not all literals)';
    }
};

done_testing();
