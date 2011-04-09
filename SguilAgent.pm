#
# Copyright (C) 2006-2007 by Victor Julien <victor@inliniac.net>
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
# Object for communication between an agent and the Sguild server.
#

my $version = "0.8-dev7";
package SguilAgent;

use fields qw ( sock sid cid select cnf pingwait pingint syslog syslogfacility );
use IO::Socket;
use IO::Socket::SSL;
use IO::Select;
use Sys::Syslog;

# chomp that removes trailing \n or \r\n
sub wrapchomp {
    for (@_) { s/^(.*?)(:?\r)?\n$/$1/ }
}

sub new {
    my $type = shift;
    my SguilAgent $self = fields::new(ref $type || $type);
	
    $self->{sock}       = undef;
    $self->{select}     = undef;
    $self->{sid}        = undef;
    $self->{cid}        = undef;
    $self->{cnf}        = undef;

    $self->{pingwait}   = undef;
    $self->{pingint}    = undef;

    $self->{syslog}     = undef;

    return $self;
}

sub version {
    my SguilAgent $self = shift;

    return $version;
}

#
# handles all tasks related to the building the
# connection.
#
sub connect {
    my SguilAgent $self = shift;

    my $ip   = $self->getvar("SERVER_HOST");
    my $port = $self->getvar("SERVER_PORT");
    my $type = $self->getvar("SENSOR_TYPE");
    my $sensor = $self->getvar("HOSTNAME");
    my $net = $self->getvar("NET_GROUP");

    my $ssl  = 0;
    eval { $ssl = $self->getvar("OPENSSL") };
    if ($@ || $ssl ne 1) {
        $ssl = 0;
    }

    # socket connect
    $self->{sock} = new IO::Socket::INET (
                        PeerAddr => $ip,
                        PeerPort => $port,
                        Proto => 'tcp' ) or die $!;

    $self->{select} = IO::Select->new();
    $self->{select}->add($self->{sock});

    # read the server version line
    my $resp = "";

    # receive the answer
    eval { $resp = $self->readline() };
    if ($@) {
        die $@;
    }
    #print "resp \"$resp\"\n";

    # if the server only accepts certain IP's, and we are not
    # using that, we get a 'Connection Refused.' line.
    if ($resp =~ /^Connection Refused.$/) {
        die "server actively refused the connection. Check your Sguild access settings";
    }

    # send our version
    my $version;
    if ( $ssl == 1 ) {
        $version = "SGUIL-0.7.0 OPENSSL ENABLED";
    } else {
        $version = "SGUIL-0.7.0 OPENSSL DISABLED";
    }

    if ($version ne $resp) {
        die "client-server version mismatch: Server is at $resp client at $version";
    }

    eval { $self->send("VersionInfo {$version}") };
    if ($@) { 
        die $@;
    }

    # initialize SSL
    if ( $ssl == 1 ) {
        eval { IO::Socket::SSL->start_SSL($self->{sock}) };
        if ($@) {
            die "start_SSL failed: $@";
        }
    }

    # send our SidCidRequest
    eval { $self->send("RegisterAgent $type $sensor $net") };
    if ($@) { 
        die $@;
    }

    # receive the answer. It looks like: AgentInfo webserver modsecurity webfarm 6 0
    eval { $resp = $self->readline() };
    if ($@) {
        die $@;
    }
    #print "Server answer $resp\n";
	
    (my $cmd, my $s, my $t, my $n, $self->{sid}, $self->{cid} ) = split (/ /, $resp);
    if (not $cmd eq "AgentInfo") {
        die "expected AgentInfo, but got: \"$cmd\"";
    }

    # increase the SID for the next alert.
    $self->incrcid();

    #print "sid $self->{sid}\ncid $self->{cid}\nname $self->{sensorname}\n";
    return;
}

sub disconnect {
    my SguilAgent $self = shift;

    if (not defined $self->{sock}) {
        die "not connected";
    }
	
    close($self->{sock}) or die $!;
    $self->{sock} = undef;
	
    return;
}

#
# Send a real time alert
#
# TODO: not yet adapted to Sguil 0.7.0
# 
sub rtevent {
    my SguilAgent $self = shift;

    if( not defined $self->{sock}) {
        die "Not connected";
    }
	
    # get the alert hash from the caller (by reference)
    my $ref = shift @_;
    my %alert = %{$ref};

    # sid, cid and sensor name come from the object
    my $sid = $self->{sid};
    my $cid = $self->{cid};
    my $sensor_name = $self->getvar ("HOSTNAME");
    my $net_name = $self->getvar ("NET_GROUP");
	
    #
    # FIRST the required data
    # sip, dip, msg, time
    if (not defined ( $alert{"sipstr"} ) || not defined ( $alert{"dipstr"} ) ) {
        die "missing data: sipstr or dipstr missing.";
    }
    if (not defined ( $alert{"sipdec"} ) || not defined ( $alert{"dipdec"} ) ) {
        die "missing data: sipdec or dipdec missing.";
    }
    if (not defined ( $alert{"msg"} ) ) {
        die "missing data: msg missing.";
    }
    if (not defined ( $alert{"time"} ) ) {
        die "missing data: time missing.";
    }
			
    # IPaddresses
    my $sip_dec = $alert{"sipdec"};
    my $sip_str = $alert{"sipstr"};
    my $dip_dec = $alert{"dipdec"};
    my $dip_str = $alert{"dipstr"};
    # Message
    my $msg = $alert{"msg"};
    # Time
    my $time = $alert{"time"};

    # timestamp
    my $ts = $time;
    if(defined $alert{"ts"} ) {
        $ts = $alert{"ts"};
    }

    # this can only be 0 it seems
    my $status = 0;

    # snort event
    my $snort_event_id = 0;
    if( defined $alert{"snort_event_id"} ) {
        $snort_event_id = $alert{"snort_event_id"};
    }
    my $snort_event_ref = 0;
    if( defined $alert{"snort_event_ref"} ) {
        $snort_event_ref = $alert{"snort_event_ref"};
    }
    my $siggen = 0;
    if( defined $alert{"siggen"} ) {
        $siggen = $alert{"siggen"};
    }
    my $sigid = 0;
    if( defined $alert{"sigid"} ) {
        $sigid = $alert{"sigid"};
    }

    # revision of the rule
    my $rev = 0;
    if( defined $alert{"rev"} ) {
        $rev = $alert{"rev"};
    }
    # priority
    my $prio = 5; # DEBUG, lowest used by Sguil.conf
    if ( defined $alert{"prio"} ) {
        $prio = $alert{"prio"};
    }
    # class
    my $class = "unknown"; # defined in snort manual
    if ( defined $alert{"class"} ) {
        $class = $alert{"class"};
    }

    # IP header
    my $ipver = 4; # default to IPv4.
    if(defined($alert{"ipver"})) {
        $ipver = $alert{"ipver"};
    }
    my $ipproto = 6; # default to TCP.
    if(defined($alert{"ipproto"})) {
        $ipproto = $alert{"ipproto"};
    }
    my $ip_hlen = 0;
    if(defined($alert{"ip_hlen"})) {
        $ip_hlen = $alert{"ip_hlen"};
    }
    my $ip_tos = 0;
    if(defined($alert{"ip_tos"})) {
        $ip_tos = $alert{"ip_tos"};
    }
    my $ip_len = 0;
    if(defined($alert{"ip_len"})) {
        $ip_len = $alert{"ip_len"};
    }
    my $ip_id = 0;
    if(defined($alert{"ip_id"})) {
        $ip_id = $alert{"ip_id"};
    }
    my $ip_flags = 0;
    if(defined($alert{"ip_flags"})) {
        $ip_flags = $alert{"ip_flags"};
    }
    my $ip_off = 0;
    if(defined($alert{"ip_off"})) {
        $ip_off = $alert{"ip_off"};
    }
    my $ip_ttl = 0;
    if(defined($alert{"ip_ttl"})) {
        $ip_ttl = $alert{"ip_ttl"};
    }
    my $ip_csum = 0;
    if(defined($alert{"ip_csum"})) {
        $ip_csum = $alert{"ip_csum"};
    }
	
    # ICMP parameters
    my $icmp_type = 0;
    if(defined($alert{"icmp_type"})) {
        $icmp_type = $alert{"icmp_type"};
    }
    my $icmp_code = 0;
    if(defined($alert{"icmp_code"})) {
        $icmp_code = $alert{"icmp_code"};
    }
    my $icmp_csum = 0;
    if(defined($alert{"icmp_csum"})) {
        $icmp_csum = $alert{"icmp_csum"};
    }
    my $icmp_id = 0;
    if(defined($alert{"icmp_id"})) {
        $icmp_id = $alert{"icmp_id"};
    }
    my $icmp_seq = 0;
    if(defined($alert{"icmp_seq"})) {
        $icmp_seq = $alert{"icmp_seq"};
    }

    # TCP/UDP ports
    my $sp = 0;
    if(defined $alert{"sp"}) {
        $sp = $alert{"sp"};
    }
    my $dp = $alert{"dp"};
    if(defined $alert{"dp"}) {
        $dp = $alert{"dp"};
    }

    # TCP header
    my $tcp_seq = 0;
    if(defined $alert{"tcp_seq"}) {
        $tcp_seq = $alert{"tcp_seq"};
    }
    my $tcp_ack = 0;
    if(defined $alert{"tcp_ack"}) {
        $tcp_ack = $alert{"tcp_ack"};
    }
    my $tcp_off = 0;
    if(defined $alert{"tcp_off"}) {
        $tcp_off = $alert{"tcp_off"};
    }
    my $tcp_res = 0;
    if(defined $alert{"tcp_res"}) {
        $tcp_res = $alert{"tcp_res"};
    }
    my $tcp_flags = 0;
    if(defined $alert{"tcp_flags"}) {
        $tcp_flags = $alert{"tcp_flags"};
    }
    my $tcp_win = 0;
    if(defined $alert{"tcp_win"}) {
        $tcp_win = $alert{"tcp_win"};
    }
    my $tcp_csum = 0;
    if(defined $alert{"tcp_csum"}) {
        $tcp_csum = $alert{"tcp_csum"};
    }
    my $tcp_urp = 0;
    if(defined $alert{"tcp_urp"}) {
        $tcp_urp = $alert{"tcp_urp"};
    }

    # UDP header
    my $udp_len = 0;
    if(defined $alert{"udp_len"}) {
        $udp_len = $alert{"udp_len"};
    }
    my $udp_csum = 0;
    if(defined $alert{"udp_csum"}) {
        $udp_csum = $alert{"udp_csum"};
    }

    # the attack payload
    my $payload = "";
    if(defined $alert{"payload"}) {
        $payload = $alert{"payload"};
    }

    #print $modsec_payload . "\n";

    # assemble the string to send to the sensor.
    #
    #           0       1       2    3    4            5              
    my $str = "RTEVENT $status $sid $cid $sensor_name " . 
    # 5               6                  7       8       9
    "$snort_event_id $snort_event_ref \{$time\} $siggen $sigid " .
    # 10    11       12    13    14  
    "$rev \{$msg\} \{$ts\} $prio $class " .
    # 15       16       17       18
    "$sip_dec $sip_str $dip_dec $dip_str " .
    # 19       20     21       22      23      24     25        26      27      28
    "$ipproto $ipver $ip_hlen $ip_tos $ip_len $ip_id $ip_flags $ip_off $ip_ttl $ip_csum " .
    # 29         30         31         32       33
    "$icmp_type $icmp_code $icmp_csum $icmp_id $icmp_seq " . 
    # 34  35
    "$sp $dp " .
    # 36       37       38       39       40         41       42        43
    "$tcp_seq $tcp_ack $tcp_off $tcp_res $tcp_flags $tcp_win $tcp_csum $tcp_urp " .
    # 44       45
    "$udp_len $udp_csum " .
    #   46
    "\{$payload\}";

    # Send the alert to the agent
    eval { $self->send($str) };
    if($@) {
        die $@;
    }

    # Read the response line
    my $resp = "";
    eval { $resp = $self->readline() };
    if($@) {
        die $@;
    }
	
    # evaluate it. We expect a line like:
    # Confirm 1854
    # where 1854 is the alert cid.
    if($resp =~ /^Confirm \d+/)
    {
        my @parsed = ($resp =~ /^Confirm (\d+)$/);
        if(@parsed == 1) {
            (my $resp_cid) = @parsed;

            if($cid != $resp_cid) {
                die "Response cid $resp_cid does not match alert cid $cid";
            }
        } else {
            die "Parsing agent response failed for: $resp";
        }
     } else {
        die "Agent returned error: $resp";
     }

     return;
}

#
# Send a real time generic alert
#
# Taken from generic_agent.tcl by Bamm Visscher:
#
# Format for GenericAlert below. Needs to be in tcl list format with
# appropriate chars escaped. See: http://www.tcl.tk/man/tcl8.5/tutorial/Tcl14.html
#
# GenericEvent status priority class hostname timestamp sensorID alertID hexMessage  \
#               inet_src_ip inet_dst_ip ip_proto src_port dst_port generatorID sigID \
#               revision hexDetail
#
# status........Status of the event. Should be 0 for RealTime
# priority......Priority of the event. Usually 1-5 with 1 being high.
# class.........Classification
# hostname......Hostname agent is running on
# timestamp.....YYYY-MM-DD HH:MM:SS (in GMT)
# agentID.......Agent ID from sguild
# alertID.......Unique number (usually incremented starting with 1)
# refID.........Reference ID if alert is associated with another
# message.......Message to be displayed when in RT event view (in hex)
# inet_src_ip...Source IP in dotted notation (192.168.1.1)
# inet_dst_ip...Dest IP in dotted notation
# ip_proto......Internet Protocol (6=TCP, 17=UDP, 1=ICMP, etc)
# src_port......Source Port
# dst_port......Dest Port
# generatorID...Unique generator ID. Each agent should have a unique generator ID.
# sigID.........Unique signature ID. Each signature for a generator should have a unique ID
# revision......Which rev of the signature
# hexDetail.....Event detail in hex. Will be displayed when analyst views the event with more detail.

sub rtgenevent {
    my SguilAgent $self = shift;

    if (not defined $self->{sock}) {
        die "Not connected";
    }
	
    # get the alert hash from the caller (by reference)
    my $ref = shift @_;
    my %alert = %{$ref};

    # sid, cid and sensor name come from the object
    my $sid = $self->{sid};
    my $cid = $self->{cid};
    my $sensor_name = $self->getvar("HOSTNAME");
    my $net_name = $self->getvar("NET_GROUP");
    my $refid = 0; # not (yet?) used
    my $genid = 10001; # Bamm Visscher tells us to use this
	
    #
    # FIRST the required data
    # sip, dip, msg, time
    if (not defined ( $alert{"sipstr"} ) || not defined ( $alert{"dipstr"} ) ) {
        die "missing data: sipstr or dipstr missing.";
    }
    if (not defined ( $alert{"sipdec"} ) || not defined ( $alert{"dipdec"} ) ) {
        die "missing data: sipdec or dipdec missing.";
    }
    if (not defined ( $alert{"msg"} ) ) {
        die "missing data: msg missing.";
    }
    if (not defined ( $alert{"time"} ) ) {
        die "missing data: time missing.";
    }

    # IPaddresses
    my $sip_dec = $alert{"sipdec"};
    my $sip_str = $alert{"sipstr"};
    my $dip_dec = $alert{"dipdec"};
    my $dip_str = $alert{"dipstr"};

    # make sure we don't send ipv6 alerts
    if (not $sip_str =~ /^\d+\.\d+\.\d+\.\d+$/) {
        return;
    }
    if (not $sip_str =~ /^\d+\.\d+\.\d+\.\d+$/) {
        return;
    }

    # Time
    my $time = $alert{"time"};

    # this can only be 0 it seems
    my $status = 0;

    my $siggen = 0;
    if (defined $alert{"siggen"} ) {
        $siggen = $alert{"siggen"};
    }
    my $sigid = 0;
    if (defined $alert{"id"} ) {
        $sigid = $alert{"id"};
    }

    # revision of the rule
    my $rev = 0;
    if (defined $alert{"rev"} ) {
        $rev = $alert{"rev"};
    }
    # priority
    my $prio = 5; # DEBUG, lowest used by Sguil.conf
    if ( defined $alert{"prio"} ) {
        $prio = $alert{"prio"};
    }
    # class
    my $class = "unknown"; # defined in snort manual
    if ( defined $alert{"class"} ) {
        $class = $alert{"class"};
    }

    my $ipproto = 6; # default to TCP.
    if (defined($alert{"ipproto"})) {
        $ipproto = $alert{"ipproto"};
    }
	
    # TCP ports
    my $sp = 0;
    if (defined $alert{"sp"}) {
        $sp = $alert{"sp"};
    }
    my $dp = $alert{"dp"};
    if (defined $alert{"dp"}) {
        $dp = $alert{"dp"};
    }

    # the message
    my $message = "";
    if (defined $alert{"hexmsg"}) {
        $message = $alert{"hexmsg"};
    }

    # the attack payload
    my $payload = "";
    if (defined $alert{"payload"}) {
        $payload = $alert{"payload"};
    }

    #print $modsec_payload . "\n";

    # assemble the string to send to the sensor.
    #
    my $str = "GenericEvent $status $prio $class $sensor_name \{$time\} " .
              "$sid $cid $refid \{$message\} $sip_str $dip_str $ipproto $sp " .
              "$dp $genid $sigid $rev \{$payload\}";

    #print "str \"$str\"\n";

    # Send the alert to the agent
    eval { $self->send($str) };
    if ($@) {
        die $@;
    }

    # Read the response line
    my $resp = "";
    eval { $resp = $self->readline() };
    if ($@) {
        die $@;
    }
    #print $resp;
	
    # evaluate it. We expect a line like:
    # Confirm 1854
    # where 1854 is the alert cid.
    #print "resp \"$resp\"\n";
    if ($resp =~ /^ConfirmEvent \d+/)
    {
        my @parsed = ($resp =~ /^ConfirmEvent (\d+)/);
        if (@parsed == 1) {
            (my $resp_cid) = @parsed;

            if ($cid != $resp_cid) {
                die "response cid $resp_cid does not match alert cid $cid";
            }
        } else {
            die "parsing server response failed for: $resp";
        }
    } else {
        die "server returned error: $resp";
    }

    return 0;
}

# Reads a line from Sguild and cuts off
# the \r\n.
sub readline {
    my SguilAgent $self = shift;

    if (not defined $self->{sock}) {
        die "Not connected";
    }

    my $line = readline ( $self->{sock} );
    unless (defined $line) {
        die "connection lost";
    }

    wrapchomp ($line);
    return $line;
}

sub send {
    my SguilAgent $self = shift;
    my $prt = shift;

    if (not defined $self->{sock}) {
        die "socket not defined";
    }

    # if select thinks we can read when we
    # expect to write, and the read result
    # is "", the connection is lost
    my @cr = $self->{select}->can_read(0);
    foreach $s (@cr) {
        my $buf = $self->{sock}->read($buf,1024);
        if (not defined $buf) {
            die "connection lost";
        }
        if ($buf eq "") {
            die "connection lost";
        }
    }

    $self->{sock}->print("$prt\r\n") or
         die "connection lost $@";
}

sub ping {
    my SguilAgent $self = shift;

    if (not defined $self->{sock}) {
        die "Not connected";
    }

    # initialize
    if (not defined $self->{pingint}) {
        # PING_DELAY is in miliseconds to
        # keep compatible with Sguil's configs
        my $i;
        eval { $i = $self->getvar("PING_DELAY") };
        if ($@) {
            $i = 0;
        } else {
            $self->{pingint} = $i / 1000;
        }
    }

    if (not defined $self->{pingwait}) {
        $self->{pingwait} = 0;
    }

    # test if we need to ping
    #
    if ($self->{pingwait} < $self->{pingint}) {
        $self->{pingwait}++;
        return;
    }

    # okay we are pinging: reset wait counter
    $self->{pingwait} = 0;

    #print "Sending PING\n";
    my $ping = "PING";

    # Send PING to the server
    eval { $self->send($ping) };
    if ($@) {
        die $@;
    }

    # Read the response line
    my $resp = "";
    eval { $resp = $self->readline() };
    if ($@) {
        die $@;
    }
    #print "resp \"$resp\"\n";

    # evaluate it. We expect a line like:
    # PONG
    if ($resp ne "PONG")
    {
        die "server returned error after PING: $resp";
    }

    return;
}

sub getcid {
    my SguilAgent $self = shift;

    return $self->{cid};
}

sub incrcid {
    my SguilAgent $self = shift;

    return $self->{cid}++;
}

sub getsid {
    my SguilAgent $self = shift;

    return $self->{sid};
}


#
#
#
sub loadcnf {
    my SguilAgent $self = shift;
    my $file = shift @_;

    if (not defined $file) {
        die "No filename supplied";
    }

    $self->{cnf} = ();

    open (FILE, $file) or
        die "can't open file: $!";

    while(<FILE>) {
        if ($_ =~ m/^set [A-z_0-9]+ .*/) {
            my @parsed = ($_ =~ /^set ([A-z_0-9]+) (.*)$/);
            (my $name, my $value) = @parsed;
            #print "name $name, value $value\n";
            $self->{cnf}{$name} = $value;
        }
    }

    # check if we have all required vars
    #
    if (not defined $self->{cnf}{SERVER_HOST} ||
        not defined $self->{cnf}{SERVER_PORT} ||
        not defined $self->{cnf}{HOSTNAME}    ||
        not defined $self->{cnf}{NET_GROUP})
    {
        die "variables mising from $file. Make sure there are at " .
            "least SERVER_HOST, SERVER_PORT, HOSTNAME, NET_GROUP";
    }

    close(FILE);
}

sub getvar {
    my SguilAgent $self = shift;
    my $varname = shift @_;

    if (not defined $self->{cnf}{$varname}) {
        die "var $varname not defined";
    }

    return $self->{cnf}{$varname};
}

sub errorlog {
    my SguilAgent $self = shift;
    my $msg = shift @_;

    $self->psyslog ( LOG_ERR , $msg );
    print "$msg\n"; # in daemon mode this is ignored
}

sub warninglog {
    my SguilAgent $self = shift;
    my $msg = shift @_;

    $self->psyslog ( LOG_WARNING , $msg );
    print "$msg\n"; # in daemon mode this is ignored
}

sub debuglog {
    my SguilAgent $self = shift;
    my $msg = shift @_;
    my $debug;

    eval { $debug = $self->getvar("DEBUG") };
    if ($@ || $debug ne 1) {
        return;
    }    

    $self->psyslog ( LOG_DEBUG , $msg );
    print "$msg\n"; # in daemon mode this is ignored
}

# semi private function for actually sending the syslog
sub psyslog {
    my SguilAgent $self = shift;
    my $priority = shift @_;
    my $msg = shift @_;

    if (not defined $self->{syslogfacility}) {
        my $f;
        eval { $f = $self->getvar("SYSLOGFACILITY") };
        if ($@) {
            $f = "daemon"; # default to daemon
        }
        $self->{syslogfacility} = $f;
    }
    if (not defined $self->{syslog}) {
        eval { Sys::Syslog::openlog ( "modsec_agent", "cons,pid", $self->{syslogfacility} ) };
        if ($@) {
            print "openlog failed: $@\n";
        }
        $self->{syslog} = 1;
    }

    eval { Sys::Syslog::syslog ( $priority, "%s", $msg ) };
    if ($@) {
        print "syslog failed: $@\n";
    }
}

1;

