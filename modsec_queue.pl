#!/usr/bin/perl -w
#
# ModSecurity for Apache (http://www.modsecurity.org)
# Copyright (c) 2002-2006 Thinking Stone (http://www.thinkingstone.com)
#
# Modified for use with Sguil by Victor Julien <victor@inliniac.net> (c) 2006-2011
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
#
# 1) Configure ModSecurity to use this script for
#    concurrent audit logging index:
#
#    SecAuditLog "|/path/to/modsec_queue.pl -c /path/to/modsec_agent.conf \
#        /path/to/auditlog/data/ \
#        /path/to/auditlog/index"
#
# 2) Restart Apache.

use MIME::Base64();
use Time::HiRes;
use Getopt::Std;
use SguilAgent;

use strict;
use warnings;
use diagnostics;

use strict "vars";
use strict "subs";

my $version = "0.8-dev7";
my $license = "GNU GPLv2. See http://www.gnu.org/licenses/gpl2.txt for more information";

# ---------------------------------------------------

my $logline_regex = "";

# hostname
$logline_regex .= "^(\\S+)";
# remote host, remote username, local username
$logline_regex .= "\\ (\\S+)\\ (\\S+)\\ (\\S+)";
# date, time, and gmt offset
$logline_regex .= "\\ \\[([^:]+):(\\d+:\\d+:\\d+)\\ ([^\\]]+)\\]";
# request method + request uri + protocol (as one field)
$logline_regex .= "\\ \"(.*)\"";
# status, bytes out
$logline_regex .= "\\ (\\d+)\\ (\\S+)";
# referer, user_agent
$logline_regex .= "\\ \"(.*)\"\\ \"(.*)\"";
# uniqueid, sessionid
$logline_regex .= "\\ (\\S+)\\ \"(.*)\"";
# filename, offset, size
$logline_regex .= "\\ (\\S+)\\ (\\d+)\\ (\\d+)";
# hash
$logline_regex .= "\\ (\\S+)";
# the rest (always keep this part of the regex)
$logline_regex .= "(.*)\$";

my $therequest_regex = "(\\S+)\\ (.*?)\\ (\\S+)";


# -- Main --------------------------------------------------------------------

my $sguil = new SguilAgent;

my %option = ();
getopts("vc:", \%option);

if ( defined $option{v} ) {
    print "\n";
    print "modsec_queue.pl version $version.\n\n";
    print "Copyright (c) 2002-2006 Breach Security Inc.\n";
    print "Copyright (c) 2006-2011 Victor Julien <victor\@inliniac.net>\n";
    print "Release under $license.\n";
    print "\n";
    exit 0;
}

if ( @ARGV != 2  || not defined $option{c}) {
    print "Usage: modsec_queue.pl -c configfile auditlog-folder auditlog-index\n";
    exit 1;
}

eval { $sguil->loadcnf ($option{c}) };
if ($@) {
    print "Loading configuration failed: $@\n";
    exit 1;
}

# username to chown the event files to
my $runas;
my $uid;
my $gid;
my $event_dir;
my $g_symlink;

eval { $runas = $sguil->getvar("RUNAS") };
if ($@) {
    $runas = "";
} else {
    my $user;
    my $group;

   ($user, $group) = split(/:/, $runas, 2);

    if (not defined $user) {
        $sguil->errorlog ( "FATAL ERROR: couldn't parse $runas: $@" );
        exit 1;
    }

    eval { $uid = getpwnam ($user) };
    if ($@) {
        $sguil->errorlog ( "FATAL ERROR: couldn't get UID for $user: $@" );
        exit 1;
    }
    if (defined $group) {
        eval { $gid = getgrnam ($group) };
        if ($@) {
            $sguil->errorlog ( "FATAL ERROR: couldn't get GID for $group: $@" );
            exit 1;
        }
    }
}

eval { $event_dir = $sguil->getvar("EVENT_DIR") };
if ($@) {
    print "FATAL ERROR: EVENT_DIR not defined in " . $option{c} . "\n";
    exit 1;
}
eval { $g_symlink = $sguil->getvar ("SYMLINK") };
if ($@ || $g_symlink eq "") {
    $g_symlink = 0;
}

my($folder, $index) = @ARGV;   

open(LOG, ">>$index") || die("Failed to open: $index\n");
$| = 1, select $_ for select LOG;

while (<STDIN>) {
    #print LOG "Line: $_";    

    chomp();
    my $summary = $_;
    my %request = ();
    
    next if (/^$/);
    
    my @parsed_logline = /$logline_regex/x;
    if (@parsed_logline == 0) {
        $sguil->warninglog ("failed to parse line: " . $_);
    } else {
        (
             $request{"hostname"},
             $request{"remote_ip"},
             $request{"remote_username"},
             $request{"username"},
             $request{"date"},
             $request{"time"},
             $request{"gmt_offset"},
             $request{"the_request"},
             $request{"status"},
             $request{"bytes_out"},
             $request{"referer"},
             $request{"user_agent"},
             $request{"unique_id"},
             $request{"session_id"},
             $request{"filename"},
             $request{"file_offset"},
             $request{"file_size"},
             $request{"hash"},
             $request{"the_rest"}
        ) = @parsed_logline;
    
        $_ = $request{"the_request"};
        my @parsed_therequest = /$therequest_regex/x;
        if (@parsed_therequest == 0) {
            $request{"invalid"} = "1";
            $request{"request_method"} = "";
            $request{"request_uri"} = "";
            $request{"protocol"} = "";
        } else {
            (
                 $request{"request_method"},
                 $request{"request_uri"},
                 $request{"protocol"}
            ) = @parsed_therequest;
        }

        # print the index file
        print LOG ($summary . "\n");
      
        # get hires time for our file timestamp.
        (my $t_sec, my $t_usec) = Time::HiRes::gettimeofday();

        # create the link...
        my $src = $folder . $request{"filename"};
        my $dst = $event_dir . "/modsec.log." . $t_sec . "." . $t_usec;

        if ($g_symlink == 1) {
            if ( symlink ( $src , $dst ) == 0 ) {
                $sguil->warninglog ( "failed to create symlink between $src and $dst" );
            }

            if ( $runas ne "" ) {
                # chown the src as the dst is the symlink itself
                eval { chown ($uid,$gid,$src) };
                if ($@) {
                    die $@;
                }
            }
        } else {
            if ( link ( $src , $dst ) == 0 ) {
                $sguil->warninglog ( "failed to create (hard)link between $src and $dst" );
            }

            if ( $runas ne "" ) {
                eval { chown ($uid,$gid,$dst) };
                if ($@) {
                    die $@;
                }
            }
        }
    }
}

close(LOG);

