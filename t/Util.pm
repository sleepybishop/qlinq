package t::Util;

use strict;
use warnings;
use Errno qw(EINTR);
use IPC::Open3 qw(open3);
use IO::Select;
use Symbol qw(gensym);

use base qw(Exporter);
our @EXPORT = qw(
	run_prog
);

sub run_prog {
	my $cmd = shift;
	if ($ENV{RUN}) {
		$cmd = "$ENV{RUN} $cmd";
	}
	# Drain both streams concurrently. Capture must not depend on temporary
	# file storage, and reading one pipe to EOF first can deadlock its sibling.
	# open3 closes its input handle in the parent, so give it a duplicate.
	open my $input_copy, '<&', \*STDIN
		or die "run_prog '$cmd' stdin duplication failed: $!\n";
	my $error_pipe = gensym;
	my $pid = open3(['&', $input_copy], my $output_pipe, $error_pipe, $cmd);
	binmode $output_pipe;
	binmode $error_pipe;
	my $output_fd = fileno($output_pipe);
	my $selector = IO::Select->new($output_pipe, $error_pipe);
	my ($stderr, $stdout) = ('', '');
	while ($selector->count) {
		for my $pipe ($selector->can_read) {
			my $count = sysread($pipe, my $chunk, 65536);
			if (!defined $count) {
				next if $! == EINTR;
				die "run_prog '$cmd' output read failed: $!\n";
			}
			if ($count == 0) {
				$selector->remove($pipe);
				close $pipe;
			} elsif (fileno($pipe) == $output_fd) {
				$stdout .= $chunk;
			} else {
				$stderr .= $chunk;
			}
		}
	}
	my $waited;
	do { $waited = waitpid($pid, 0); } while ($waited < 0 && $! == EINTR);
	die "run_prog '$cmd' wait failed: $!\n" if $waited != $pid;
	my $exit_code = $?;
	print STDERR "run_prog '$cmd' exited with status: $exit_code\n";
	# A success marker printed before an exit-time sanitizer error must not
	# turn a failing process into a passing test. All callers run test programs
	# whose own expected-error scenarios still exit successfully.
	die "run_prog '$cmd' failed with status $exit_code\n$stderr\n$stdout"
		if $exit_code != 0;
	return ($stderr, $stdout);
}

1;
