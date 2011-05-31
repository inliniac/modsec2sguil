#!/usr/bin/perl -w

#
# Copyright (C) 2006-2011 by Victor Julien <victor@inliniac.net>
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
# along with this program; if not, write to the
# Free Software Foundation, Inc.,
# 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

# Agent for feeding ModSecurity alerts to the Sguil NSM system.
# 
# Reads files or symlinks from the queue directory, feeds them
# to Sguil and removes the file/symlink.
#

use strict;
use warnings;
use diagnostics;

use IO::Socket;
use DirHandle;
use Getopt::Std;
use Time::Local;
use POSIX 'setsid';

use ModsecAlert;
use SguilAgent;

use strict "vars";
use strict "subs";

my $version = "0.8";
my $license = "GNU GPLv2. See http://www.gnu.org/licenses/gpl2.txt for more information";

#
# CONVERSION FUNCTIONS
#

sub ConvertASCIItoHEX
{
    my $asciistr = shift @_;

    my $hexstr = join '', unpack "H*", $asciistr;
    #print $hexstr . "\n";

    return($hexstr);
}

#
# This doesn't return 5, the lowest for Sguil because we use that for
# non-alert events
#
sub ConvertSEVERITYtoPRIO
{
    my $severity = shift @_;

    my %sev = ( "EMERGENCY" => 1,
                "ALERT"     => 1,
                "CRITICAL"  => 2,
                "ERROR"     => 2,
                "WARNING"   => 3,
                "NOTICE"    => 3,
                "INFO"      => 4,
                "DEBUG"     => 4 );

    if (not defined $sev{$severity}) {
        return 4; # default to 4 which is the lowest we use for alerts
    }

    return $sev{$severity};
}

sub ConvertMONTHSTRtoDEC
{
    my $monthstr = shift;

    my %mon = ( "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
                "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
                "Sep" => 9, "Oct" => 10,"Nov" => 11,"Dec" => 12 );

    if (not defined $mon{$monthstr}) {
        return -1;
    }

    return $mon{$monthstr};
}

sub ConvertIPtoDEC
{
    my $ip = shift;
        
    if (not $ip =~ /^\d+\.\d+\.\d+\.\d+$/) {
        return(0);
    }

    ( my $one , my $two , my $three , my $four ) = split(/\./, $ip);
    my $dec = $one * 16777216 + $two * 65536 + $three * 256 + $four;

    return($dec);
}


#
# ALERT PROCESSING
#

#
# Some preprocessing before sending the alert
# to Sguil.
#
# This function is only called for actual alerts.
#
# Returns:  -1 on error
#       0 on success
#
sub PreprocessAlert
{
    # get the alert hash from the caller (by reference)
    my $ref = shift @_;

    #
    # SECTION A
    #

    # stupid trick to convert month(str) to month(dec)
    my $month = ConvertMONTHSTRtoDEC $ref->{"monthstr"};
    if ($month != -1) {
        $ref->{"month"} = $month;
    } else {
        print "Month parse failed.\n";
        return -1;
    }

    # convert sipstr and dipstr to dec as well
    $ref->{"sipdec"} = ConvertIPtoDEC $ref->{"sipstr"};
    $ref->{"dipdec"} = ConvertIPtoDEC $ref->{"dipstr"};

    # timezone handling: the time/date is logged like this:
    # 13/Aug/2006:21:59:24 +0200, which is 19:59.24 UTC. In
    # Sguil we want the UTC value, so we convert it here.
    # 
    # first parse the timestring
    (my $hour, my $min, my $sec ) = split(/:/, $ref->{"timestr"});

    # get the unixtime in gm, month is from 0 to 11.
    my $time = timegm($sec,$min,$hour,$ref->{"day"},$ref->{"month"}-1,$ref->{"year"});

    # parse the timezone offset. It looks like +0200 or -0100
    $_ = $ref->{"tz"};
    my @parse = /(.{1})(\d{2})(\d{2})$/;
    if (@parse == 0) {
        print "Parsing timezone information failed.\n";
        return -1;
    } else {
        (my $op, my $tz_hour, my $tz_min) = @parse;
        my $tz_val = $tz_hour * 3600 + $tz_min * 60;

        # +0200 means we have to subtrackt 2 hrs to get UTC
        if ( $op eq "+" ) {
            $time -= $tz_val;
        } elsif ( $op eq "-" ) {
            $time += $tz_val;
        } else {
           print "Unknown operator $op in timezone string " . $ref->{"tz"} . "\n";
           return -1;
        }

        #print "time after tz apply: $time, gmtime " . gmtime($time) . "\n";

        # convert the new unix time
        # Fri Aug 18 04:35:35 2006
        # Mon Aug  7 07:51:23 2006 <= note two spaces, split(/ / won't work
        # that is what the \ ? takes care of.
        # 
        # update day, timestr and year
        $_ = gmtime($time);
        @parse = /(\S*) (\S*) \ ?(\d*) (.*) (\d+)/;
        if ( @parse == 0 ) {
            print "Date/time parsing error, parsing $_ failed\n";
            return -1;
        } else {
            (my $dayname, $ref->{"monthstr"}, $ref->{"day"}, $ref->{"timestr"}, $ref->{"year"} ) = @parse;
        }

        # update month
        $month = ConvertMONTHSTRtoDEC $ref->{"monthstr"};
        if ($month != -1) {
            $ref->{"month"} = $month;
        } else {
           print "Month parse failed, parsing " . $ref->{"monthstr"} . ".\n";
           return -1;
        }

        #print $ref->{"timestr"} . "\n";
    }

    # add a padding zero to match the barnyard behaviour.
    if ( $ref->{"day"} < 10 ) {
        $ref->{"day"} = "0" . $ref->{"day"};
    }
    if ( $ref->{"month"} < 10 ) {
        $ref->{"month"} = "0" . $ref->{"month"};
    }

    $ref->{"time"} = $ref->{"year"} . "-" . $ref->{"month"} . "-" . $ref->{"day"} . " " . $ref->{"timestr"};

    #
    # SECTION H
    #

    # check for a message with a message, get it?
    if( defined( $ref->{"themsg"} ) ) {
        #print "themsg: " .  $ref->{"themsg"} . "\n";
        ($ref->{"rev"})    = ($ref->{"themsg"} =~ /.*\[rev \"(\d+)\"\].*/);
        ($ref->{"id"})     = ($ref->{"themsg"} =~ /.*\[id \"(\d+)\"\].*/);
        ($ref->{"themsg"}) = ($ref->{"themsg"} =~ /.*\[msg \"(.*)\"\].*/);

        #if (defined $ref->{"rev"}) { 
        #    print "REV " . $ref->{"rev"} . "\n";
        #}
        #if (defined $ref->{"themsg"}) { 
        #    print "MSG " . $ref->{"themsg"} . "\n";
        #}
        #if (defined $ref->{"id"}) { 
        #    print "ID  " . $ref->{"id"} . "\n";
        #}
    }

    # lets see what kind of class we are going to use
    # we use *-attack for stuff that is blocked, *-activity
    # for the rest
    if ($ref->{"code"} < 400) {
        $ref->{"class"} = "web-application-activity";
        $ref->{"prio"} = 5; # lowest prio
    } else {
        $ref->{"class"} = "web-application-attack";
        $ref->{"prio"} = ConvertSEVERITYtoPRIO $ref->{"severity"};
    }

    # Event message
    if ((not defined $ref->{"themsg"}) || ($ref->{"themsg"} eq "")) {
        $ref->{"themsg"} = $ref->{"http_response_reason_phrase"};
    }
    $ref->{"msg"} = "MSc " . $ref->{"code"} . " " . $ref->{"themsg"};

    # hex the message
    $ref->{"hexmsg"} = ConvertASCIItoHEX $ref->{"msg"};

    # hex the payload
    $ref->{"payload"} = ConvertASCIItoHEX $ref->{"file"};

    return 0;
}

# tries to drop privs to $string
# $string can be either "user" or "user:group"
sub RunAs {
    my $string = shift @_;

    my $user;
    my $group;

    ($user, $group) = split(/:/, $string, 2);

    if (not defined $user) {
        return;
    }
    if ($user eq "") {
        return;
    }

    my $curname = getpwuid($<);
    my $curuid  = getpwnam($curname);

    my $newuid = 0;
    eval { $newuid = getpwnam($user) };
    if ($@) {
        die $@;
    } elsif (not defined $newuid) {
        die "getpwnam for $user failed";
    }

    if ($curuid == $newuid) {
        return;
    }

    my $newgid = $(;
    if (defined $group && $group ne "") {
        $newgid = getgrnam($group);
        if (not defined $newgid) {
            die "getgrnam for $group failed";
        }
    }

    # set the new uid
    $( = $) = $newgid;
    $< = $> = $newuid;

    return;
}

sub Daemonize
{
    $| = 1;

    chdir '/'                 or die "Can't chdir to /: $!";
    open STDIN, '/dev/null'   or die "Can't read /dev/null: $!";
    open STDOUT, '>/dev/null' or die "Can't write to /dev/null: $!";
    defined(my $pid = fork)   or die "Can't fork: $!";
    exit if $pid;
    setsid                    or die "Can't start a new session: $!";
    open STDERR, '>&STDOUT'   or die "Can't dup stdout: $!";
}


#
# Returns a list of filenames of event files.
# Returns 0 if no files were found.
#
sub GetAlertFiles {
    my $dir = shift;
    #print $dir . "\n";

    my $dh = DirHandle->new($dir) or die "can't open dir $dir: $!\n";
    return sort
           grep { /^$dir\/modsec\.log\..*/ } # we want only the files that start with modsec.log.
           map  { "$dir/$_" }
           grep { !/^\./    }
           $dh->read();
}

#
# START MAIN
#

my $sguil = new SguilAgent;

# global vars
my %g_ignore_http_codes = ();
my $g_handle_all_events = 0;
my $g_event_dir;
my $g_runas = "";
my $g_debug = 0;
my $g_daemon = 0;
my $g_symlink = 0;
my $g_symlink_rm_orig = 0;

# fill the g_ignore_http_codes hash
sub GetIgnoreCodes {
    my $codes;
    my @list;
    eval { $codes = $sguil->getvar ("IGNORE_HTTP_CODES") };
    if ($@ || $codes eq "") {
        return;
    }

    @list = split (/ /, $codes);
    foreach my $code (@list) {
        $g_ignore_http_codes{$code} = 1;
    }
}

# returns 1 if the code is in the ignore list
# returns 0 otherwise
sub TestIgnoreCode {
    my $code = shift;

    if (not defined $g_ignore_http_codes{$code}) {
        return 0;
    }

    return 1;
}

sub process_events {
    my $event_dir = shift @_;

    while ( 1 )
    {
        my @list = GetAlertFiles ( $event_dir );
        if ( @list == 0 ){
            # only print these when debug is 2 to prevent flooding the logs
            if ($g_debug == 2) {
                $sguil->debuglog ("No eventfiles, sleeping for a second." );
            }
            $sguil->ping();
            sleep 1;
        }
        else
        {
            # parse each file and check if it really was an alert
            foreach my $file (@list) {
                $sguil->debuglog ( "Eventfile found: $file." );
                my $valid = 0;

                if (-l $file) {
                    my $real_file = readlink($file);
                    $sguil->debuglog ( "Symlink $file to $real_file." );
                    if (-r $real_file) {
                        $valid = 1;
                    } else {
                        $sguil->debuglog ( "real file doesn't exist" );
                    }
                } else {
                    if(-r $file) {
                        $valid = 1;
                    } else {
                        $sguil->debuglog ( "file doesn't exist" );
                    }
                }

                if ($valid == 1) {
                    # get a ModsecAlert object
                    my $alert = new ModsecAlert;

                    # parse the alert file
                    eval { $alert->parsefile( $file ) };
                    if ($@) {
                        die $@;
                    }

                    # get a copy from the hash of the alert
                    my %event_hash = %{$alert->getalerthash()};
                    # create a reference to work with
                    my $hash_ref = \%event_hash;

                    # Determine if we will continue processing the event.
                    #
                    if (exists($event_hash{"code"}) &&
                            ($event_hash{"code"} ge 400 || $g_handle_all_events == 1) &&
                            TestIgnoreCode($event_hash{"code"}) == 0)
                    {
                        # preprocess the data so it becomes what Sguil expects
                        if ( PreprocessAlert ( $hash_ref ) == 0 ) {
                            $sguil->debuglog ( "Processing Event \"" . $event_hash{"themsg"} . "\"" );

                            # send the event as a GenericEvent to Sguild
                            eval { $sguil->rtgenevent( $hash_ref ) };
                            if ($@) {
                                die $@;
                            }

                            # increase the cid so the next event gets it's uniq cid.
                            $sguil->incrcid();

                            $sguil->debuglog ( "Event accepted by server." );
                        }
                    }
                } else {
                    print "removing invalid file\n";
                }

                if ($g_symlink == 1 && $g_symlink_rm_orig == 1) {
                    my $orig_file = readlink($file);
                    if (defined $orig_file && $orig_file ne "") {
                        $sguil->debuglog ( "Original file to remove: $orig_file" );

                        my $rem = unlink ($orig_file);
                        if ($rem != 1 ) {
                            $sguil->warninglog ( "warning could not remove $orig_file: $!" );
                        }
                    }
                }

                my $removed = unlink ($file);
                if ($removed != 1 ) {
                    # fatal error, because we keep processing the same
                    # event over and over again if it wasn't removed.
                    $sguil->errorlog ( "FATAL ERROR: could not remove $file: $!" );
                    exit 1;
                }
            }
        }
    }
}


#
# option parsing
# 
my %option = ();
getopts("vc:", \%option);

if ( defined $option{v} ) {
    my $modsec = new ModsecAlert;
    print "\n";
    print "modsec_agent.pl version $version (ModsecAlert.pm " . $modsec->version() . ", SguilAgent.pm " . $sguil->version() . ").\n\n";
    print "Copyright (c) 2006-2011 by Victor Julien <victor\@inliniac.net>.\n";
    print "Released under $license.\n";
    print "\n";
    exit 0;
}

# Load the configution file.
#
eval { $sguil->loadcnf($option{c}) };
if ($@) {
    print "FATAL ERROR: loading configuration file \"" . $option{c} . "\" failed: $@\n";
    exit 1;
}

# Get from the config what we need right here.
#

# See if we want to drop privs and if so, do it
# asap.
eval { $g_runas = $sguil->getvar("RUNAS") };
eval { RunAs($g_runas) };
if ($@) {
    print "FATAL ERROR: dropping privs failed: $@\n";
    exit 1;
}

# we require EVENT_DIR for picking up events.
eval { $g_event_dir = $sguil->getvar ("EVENT_DIR") };
if ($@ || $g_event_dir eq "") {
    print "FATAL ERROR: EVENT_DIR variable missing or invalid, please review your configuration file.\n";
    exit 1;
}


eval { $g_symlink = $sguil->getvar ("SYMLINK") };
if ($@ || $g_symlink eq "") {
    $g_symlink = 0;
}
eval { $g_symlink_rm_orig = $sguil->getvar ("SYMLINK_REMOVE_ORIGINAL") };
if ($@ || $g_symlink_rm_orig eq "") {
    $g_symlink_rm_orig = 0;
}
eval { $g_handle_all_events = $sguil->getvar ("HANDLE_ALL_EVENTS") };
if ($@ || $g_handle_all_events eq "") {
    $g_handle_all_events = 0;
}
eval { $g_debug = $sguil->getvar ("DEBUG") };
if ($@ || $g_debug eq "") {
    $g_debug = 0;
}
GetIgnoreCodes();
eval { $g_daemon = $sguil->getvar("DAEMON") };
if ($@ || $g_daemon ne 1) {
    $g_daemon = 0;
}

#
# Okay, let do daemon if we are configured to.
#
if ( $g_daemon == 1 ) {
    Daemonize();
}

#
# Main processing loop. We connect, process events, reconnect.
#
while (1) {
    my $done = 0;

    # Try to connect. Retry every 5 seconds until it succeeds.
    while ($done == 0) {
        eval { $sguil->connect () };
        if ($@) { 
            $sguil->warninglog ("Setting up the connection to the server failed: $@");
            sleep(5);
        } else {
            $done = 1;
        }
    }
    $sguil->debuglog ( "Connected to server" );

    eval { process_events($g_event_dir) };
    if ($@) {
        $sguil->errorlog ( "processing events failed: $@" );
    }

    eval { $sguil->disconnect() };
    if ($@) {
        $sguil->errorlog ( "FATAL ERROR: closing connection problem: $@" );
        exit 1;
    }
}

exit 0;

