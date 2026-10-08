# -*- indent-tabs-mode: nil; -*-
# DKIM2 Message-Instance support.
use strict; use warnings;
use Test::More;
use Sympa::Config::Schema;

subtest 'switch parameter' => sub {
    my %p = %{ $Sympa::Config::Schema::pinfo{dkim2_message_instance} || {} };
    ok %p, 'defined';
    is_deeply $p{format}, ['on', 'off'], 'on/off';
    is $p{default}, 'off', 'default off';
    is_deeply $p{context}, [qw(list domain site)], 'list/domain/site';
};

done_testing;
