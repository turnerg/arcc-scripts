#!/usr/bin/perl
use Fcntl;
use POSIX qw(tmpnam);
use strict;

my ($stat,$sig,$cored); 

# where are SLURM binaries installed
my $SROOT="/usr/bin";   
# a centrally located log file
my $logfile = "~turnergg/terminated.orphans.txt";
# hostname
my $hn=`/bin/hostname`;
$stat   = $? >> 8;
$sig   = $? & 0x7f;
$cored = $? & 0x80;
if ( $stat != 0 ) {
  print "Error on hostname\n";
  print "Error Status=$stat Signal=$sig CoreDumped=$cored 1\n";
  exit 1;
}
chomp($hn);
#print "$hn\n";
# pid hash tree
my %pidtree;
# a diagnostic string built during the recursive calls looking for the parent root node
my $diagstr;

# list of users to never kill
my @ignoreusers = qw(turnergg schartlm steelear root rpc rpcuser ntp daemon nobody 
	sshd smmsp zabbix polkitd postfix dbus );


# build list of users SLURM has allocated to this node and append to ignoreusers list
#print "$SROOT/squeue -w $hn -o \"%.8u\" | grep -v USER|\n";
open(UL, "$SROOT/squeue -w $hn -o \"%.8u\" | grep -v USER|");
# DEBUGGING   temp-input.txt has the example output from "$SROOT/squeue -w dl3 -o \"%.8u\" | grep -v USER
# open(UL, "<", "./temp-input.txt") or die "Can't open < temp-input.txt: $!";
while (<UL>) {
  chomp();
  #print "$_\n";
  my ($user) = split(" ",$_);
  #print "|$u|\n";
  push (@ignoreusers,$user);
}
close(UL);
#print "@ignoreusers\n";

# Build hash of users that will not be killed
my %ignore_user;
my @exempt = @ignoreusers;
map { $ignore_user{$_} = 1 } @exempt;

#---------------------------------------------------------

# main work starts here

#
# create a tree of all the processes running on this node
#
build_pidtree();

#
# loop through all pid's looking for processes that should not be here.
#
foreach my $pid (keys %pidtree) {
  $diagstr="\n";
  my ($un, $tpid, $ppid, $cpus, $stime, $tty, $rtime, $run_time, $cmd) = @{$pidtree{$pid}};
  #print"$un, $tpid, $ppid, $cpus, $stime, $tty, $rtime, $run_time, $cmd\n";
  next if (exists($ignore_user{$un}));
  next if (is_parent_ok($pid));

# If you get to here, then this process should not be on this node

  #print "NotOK: $un, $tpid, $ppid, $cpus, $stime, $tty, $rtime, $run_time, $cmd\n";
  #print "$diagstr\n";
  if ( $#ARGV == 0 ) { # if there are ARGuments...
    if ( $ARGV[0] eq "kill") { # ...and the first ARG is kill, then really kill processes
	  # the kill command
	  # uncomment this to really kill orphaned processes
      #my $retval = kill 'KILL', $pid ;
      #open(LOG, ">>$logfile");
      #print LOG "$date $hn $un $pid $ppid $cpus $stime $tty $rtime $run_time $cmd\n";
      #close(LOG);
      print"DEBUG killing $hn $un $pid $ppid $cpus $stime $tty $rtime $run_time $cmd\n";
    }
  } else { # ...otherwise, if no ARG then just print the processes we would have killed
    print"NOT auth $hn $un $pid $ppid $cpus $stime $tty $rtime $run_time $cmd\n";
  }

#---------------------------------------------------------

}


exit 0; # all done

#------------------------------------------

#------------------------------------------

#
# build_pidtree()
#
#   whose related to whom....
#
sub build_pidtree {
  my $ps_cmd = '/bin/ps -efal';
  my $re_pids  = '(\d+)\s+(\d+)\s+(\d+)';
  my $re_stime = '([A-Z][a-z]{2}\s+\d+|\d+:\d+:\d+)';
  my $re_rtime = '(\d+:\d+)';

  my $re_ps = join('', '^\s*(\S+)\s+',
              $re_pids, '\s+',
              $re_stime, '\s+(\S+)\s+',
              $re_rtime, '\s+(.*)');
    
  my ($f,$s,$un,$pid,$ppid,$cpus,$pri,$ni,$addr,$sz,$wchan,$stime,$tty,$rtime,$cmd);
  my %parent;

  open(PS,"$ps_cmd|");
  while (<PS>) {
    chomp();
    #print "$_\n";
    next if /^\s+UID/;
    next if /^UID/;
    next if /UID/;
    ($f,$s,$un,$pid,$ppid,$cpus,$pri,$ni,$addr,$sz,$wchan,$stime,$tty,$rtime,$cmd) = split(" ",$_,15);
    #print "$un $pid $ppid $cpus $stime $tty $rtime $cmd\n\n";

    # Help build up our process tree
    $parent{$pid} = $ppid;

    # Compute run time in seconds
    my ($run_hrs, $run_mins, $run_secs) = split(/:/, $rtime);
    $_ = $run_hrs;
    if ( /-/ ) {
      my ($run_days_tmp,$run_hrs_tmp) = split("-",$run_hrs);
      $run_hrs = 24 * $run_days_tmp + $run_hrs_tmp;
    } 
    my $run_time = 3600*$run_hrs + 60*$run_mins + $run_secs;
    # Cache processes and their info
    $pidtree{$pid} = [ $un, $pid, $ppid, $cpus, $stime, $tty,
		     $rtime, $run_time, $cmd ] ;
    #print "@{$pidtree{$pid}}\n";
  
  }
  close(PS);
} # end build_pidtree()


#------------------------------------------


# is_parent_ok($pid)
#
#   Walk the process tree to see if a process' parent
#   is an acceptable command
#
sub is_parent_ok {
  my $pid = shift;

  my ($un, $tpid, $ppid, $cpus, $stime, $tty, $rtime, $run_time, $cmdline) =
    @{$pidtree{$pid}};

  my $returnvalue = 0 ;
  $_ = $cmdline ;

  if (/slurmstepd:/)  {          # redundant; user is discovered by squeue cmd above
    $returnvalue = 1 ;
    print "\n\nWinner\n$pid $ppid $un $run_time $cmdline\n" ;
    #$diagstr .= "\nWinner\n$pid $ppid $un $run_time $cmdline\n" ;
    #print "$returnvalue $diagstr\n";
    return $returnvalue ;
  } elsif ($ppid <= 2 ) {         # parent is init, systemd, or kthreadd
    $returnvalue = 0 ;
    #print "\n\nLooser\n$pid $ppid $un $run_time $cmdline\n" ;
    #$diagstr .= "\nLooser\n$pid $ppid $un $run_time $cmdline\n" ;
    #print "$returnvalue $diagstr\n";
    return $returnvalue ;
  } else {                        # check the parent of this process
    $returnvalue = is_parent_ok($ppid) ;
    #print "$pid $ppid $un $run_time $cmdline\n" ;
    #$diagstr .=  "$pid $ppid $un $run_time $cmdline\n" ;
    #print "$returnvalue $diagstr\n";
    return $returnvalue ;
  }

} # end is_parent_ok()


