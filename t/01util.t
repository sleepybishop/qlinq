use strict;
use warnings;
use Test::More;
use t::Util;
use Digest::SHA qw(sha256_hex);

my ($stderr, $stdout) = run_prog(q{perl -e 'print "success\n"'});
is($stdout, "success\n", 'successful child output is preserved');
my $ok = eval { run_prog(q{perl -e 'print "===SUCCESS===\n"; warn "exit-time failure\n"; exit 7'}); 1 };
ok(!$ok, 'a success marker cannot hide a nonzero child exit');
like($@, qr/exit-time failure/, 'child failure diagnostics are retained');

# Keep the outer reader on a pipe, then prohibit regular-file output only in
# the child. A tempfile-based inner capture cannot preserve this marker.
open my $limited, '-|', 'sh', '-c', q{ulimit -f 0; exec perl -I. -Mt::Util -e 'my ($err, $out) = run_prog(q{printf file-limit-marker}); die "missing marker" unless $out eq "file-limit-marker"; print "captured\n"'}
    or die "file-limited child: $!";
my $limited_output = do { local $/; <$limited> };
my $limited_success = close $limited;
ok($limited_success && $limited_output eq "captured\n",
    'capture preserves output when regular-file writes are prohibited');

($stderr, $stdout) = run_prog(q{perl -e 'for (1..32) { print STDOUT "o" x 65536; print STDERR "e" x 65536; }'});
is(length($stdout), 32 * 65536, 'large stdout stream is fully drained');
is(sha256_hex($stdout), sha256_hex('o' x (32 * 65536)), 'large stdout bytes are intact');
is(length($stderr), 32 * 65536, 'large stderr stream is fully drained');
is(sha256_hex($stderr), sha256_hex('e' x (32 * 65536)), 'large stderr bytes are intact');

{
    pipe(my $reader, my $writer) or die "stdin pipe: $!";
    print {$writer} "inherited input\n";
    close $writer or die "close stdin pipe: $!";
    open my $original_input, '<&', \*STDIN or die "save stdin: $!";
    open STDIN, '<&', $reader or die "replace stdin: $!";
    ($stderr, $stdout) = run_prog(q{perl -e 'my $line = <STDIN>; print "echo:$line"'});
    is($stdout, "echo:inherited input\n", 'child still inherits caller input');
    ok(defined fileno(STDIN), 'capture leaves caller stdin open');
    open STDIN, '<&', $original_input or die "restore stdin: $!";
}
done_testing;
