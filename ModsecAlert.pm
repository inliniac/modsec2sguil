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
# Object for parsing ModSecurity autitlog event files.
#

my $version = "0.8-dev7";
package ModsecAlert;

use fields qw (	store );

sub new {
    my $type = shift;
    my ModsecAlert $self = fields::new(ref $type || $type);

    $self->{store} = undef;

    return $self;
}

sub version {
    my ModsecAlert $self = shift;

    return $version;
}

#
# Returns a COPY of the alert hash
#
sub getalerthash {
    my ModsecAlert $self = shift;

    return $self->{store};
}

#
# Takes the location of a file as argument, 
# opens it, parses it and stores it into
# the $self->{store} hash.
#
sub parsefile {
    my ModsecAlert $self = shift;
    my $filename = shift;

    my $line_num = 1;
    my $fileid;
    my $section = "-";
    my %event;
    my @reqhd; # request headers
    my @rsphd; # response headers

    # initialize some vars in case the alert doesn't contain them
    $self->{store}{"file"} = "";
    $self->{store}{"themsg"} = "";
    $self->{store}{"http_request_body"} = "";
    $self->{store}{"severity"} = "DEBUG"; # lowest by modsec
    $self->{store}{"rev"} = 0;
    $self->{store}{"http_request_urlencoded"} = 0;

    $self->{store}{"http_request_protocol"} = "";
    $self->{store}{"http_response_protocol"} = "";

    open (FILE , $filename) or
        die "Could not open file $filename: $!\n";

    while (<FILE>)
    {
        # store all lines of the file so we can use it
        # as the alert payload later
        $self->{store}{"file"} = $self->{store}{"file"} . $_;

        # Get this file's unique id
        if ($line_num == 1)
        {
            my @parsed_line = /^--(\S+)-A--$/;
            if ( @parsed_line == 0 ) {
                goto error;
            } else {
                #print "parsed line @parsed_line\n";

                ( $fileid ) = @parsed_line;
                #print "fileid " . $fileid . "\n";
            }
        }	
        # parse the section character
        if ( /^--$fileid-\S+--$/ ) {
            my @parsed_line = /^--$fileid-(\S+)--$/;
            ( $section ) = @parsed_line;
            #print "section " . $section . "\n";
        }
        #section A -- time, ipaddresses and ports
        elsif ($section eq "A")
        {
            if (m/^\[.*\] .*$/) {
                my @parsed_line = /^\[(\d+)\/(\S+)\/(\d+):(.*) (.*)\] (\S+) (\S+) (\d+) (\S+) (\d+)$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    ( $self->{store}{"day"}, $self->{store}{"monthstr"}, $self->{store}{"year"},
                      $self->{store}{"timestr"}, $self->{store}{"tz"}, $self->{store}{"uniqueid"},
                      $self->{store}{"sipstr"}, $self->{store}{"sp"}, $self->{store}{"dipstr"},
                      $self->{store}{"dp"} ) = @parsed_line;

                      # all further processing is done only if we know this
                      # is an alert. PreprocessAlert processes it further.
                }
            }
        }
        #section B request headers
        elsif ( $section eq "B" )
        {
            my @header_list;

            if ( m/^\S+ .* HTTP\/\d\.\d$/ )
            {
                my @parsed_line = /^(\S+) (.*) (\S+)$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    ( $self->{store}{"http_request_method"} , $self->{store}{"http_request_uri"} , $self->{store}{"http_request_protocol"} ) = @parsed_line;
                }
            } elsif ( m/^\S+\: .*$/ ) {
                my @parsed_line = /^(\S+)\: (.*)$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    my %header;

                    ( $header{"name"} , $header{"value"} ) = @parsed_line;
                    push(@reqhd, \%header);

                    # A bit hackish, but this saves us walking the list
                    # for a second time later
                    if ( ($header{"name"} eq "Content-Type" ) &&
                         ($header{"value"} eq "application/x-www-form-urlencoded")) {
                        $self->{store}{"http_request_urlencoded"} = 1;
                    }
                }
            }
            # handle "GET /"
            elsif ( m/^\S+ .*/ )
            {
                my @parsed_line = /^(\S+) (.*)$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    ( $self->{store}{"http_request_method"} , $self->{store}{"http_request_uri"} ) = @parsed_line;
                }
            }
            # Store the list in our object
            $self->{store}{"http_request_headers"} = \@reqhd;

            #print "DEBUG: headers ".$self->{store}{"http_request_headers"}." ".@reqhd."\n";
        }
        #section C request body
        elsif ( $section eq "C" )
        {
            $self->{"store"}{"http_request_body"} = $self->{"store"}{"http_request_body"} . $_;
        }
        # section F request response
        # can in some cases be completely empty
        elsif ( $section eq "F" )
        {
            if ( m/^HTTP\/\d\.\d \d+ .*/ )
            {
                my @parsed_line = /^(\S+) (\d+) (.*)$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    ( $self->{store}{"http_response_protocol"} , $self->{store}{"code"} , $self->{store}{"http_response_reason_phrase"} ) = @parsed_line;
                }
            }
        }
        #section H, alert info, mod_sec response
        elsif ( $section eq "H" )
        {
            # ModSecurity 1.9.4
            if ( m/^Message\: Access denied with code \d+\. .*/ )
            {
                my @parsed_line = /^Message\: Access denied with code (\d+)\. (.*) \[severity \"(\S+)\"\]$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    ( $self->{store}{"code"} , $self->{store}{"themsg"} , $self->{store}{"severity"} ) = @parsed_line;
                }
            }
            # Modsecurity 2.5 adds a tag at the end of the line now for classification,
            # Thanks to Ryan Cummings.
            elsif ( m/^Message\: Access denied with code \d+ \(phase \d\)\. .*\[severity \"\S+\"\] (\[tag \"(\S+)\"\])?/ )
            {
                my @parsed_line = /^Message\: Access denied with code (\d+) \(phase \d\)\. (.*) \[severity \"(\S+)\"\] (\[tag \"(\S+)\"\])?$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    ( $self->{store}{"code"} , $self->{store}{"themsg"} , $self->{"store"}{"severity"} ) = @parsed_line;
                }
            }
            # ModSecurity 2.x -- adds phase, and no longer adds severity
            # but sometimes it does:
            # example: Message: Access denied with code 403 (phase 2). Unconditional match in SecAction. [msg "LOCAL comment spam: forbidden word"] [severity "DEBUG"]
            # So look for a line with severity first
            elsif ( m/^Message\: Access denied with code \d+ \(phase \d\)\. .*\[severity \"\S+\"\]/ )
            {
                my @parsed_line = /^Message\: Access denied with code (\d+) \(phase \d\)\. (.*) \[severity \"(\S+)\"\]$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    ( $self->{store}{"code"} , $self->{store}{"themsg"} , $self->{"store"}{"severity"} ) = @parsed_line;
                }
            }
            elsif ( m/^Message\: Access denied with code \d+ \(phase \d\)\. .*/ )
            {
                my @parsed_line = /^Message\: Access denied with code (\d+) \(phase \d\)\. (.*)$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    ( $self->{store}{"code"} , $self->{store}{"themsg"} ) = @parsed_line;
                    $self->{"store"}{"severity"} = 0;
                }
            }
            elsif ( m/^Message\: Access denied with redirect to.*/ )
            {
                my @parsed_line = /^Message\: Access denied with redirect to \[(.*)\]\. (.*) \[severity \"(\S+)\"\]$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                   ( $self->{store}{"redirecturl"} , $self->{store}{"themsg"} , $self->{store}{"severity"} ) = @parsed_line;
                }
            }
            # Apache-Error: [file "/build/buildd/apache2-2.0.55/build-tree/apache2/modules/aaa/mod_access.c"] [line 282] [level 3] client denied by server configuration: /var/www/cgi-bin
            elsif ( m/^Apache-Error\: \[file .*\] .* \[level \d+\] .*/ )
            {
                #print "ModsecAlert.pm: Apache Error!\n";
                my @parsed_line = /^Apache-Error\: \[file .*\] .* \[level \d+\] (.*)$/;
                if ( @parsed_line == 0 ) {
                    goto error;
                } else {
                    ( $self->{store}{"themsg"} ) = @parsed_line;
                    $self->{store}{"themsg"} = "Apache-Error: " . $self->{store}{"themsg"};
                }
                #print "msg \"" . $self->{store}{"themsg"} . "\"\n";
            }

            # if we do not yet have a code (e.g. in a redirect case)
            # we try to find it here
            if (not defined($self->{store}{"code"}) )
            {
                if (m/^Action\: Intercepted \((\d+)\).*/)
                {
                    my @parsed_line = /^Action\: Intercepted \((\d+)\)$/;
                    if ( @parsed_line == 0 ) {
                        goto error;
                    } else {
                        ( my $code ) = @parsed_line;
                        #print "Action " . $code . "\n";
                        $self->{store}{"code"} = $code;
                    }
                }
            }
        }#sections done
        $line_num++;
    }

    close(FILE);
    return;

    # a bit ugly, but it saves us from duplicating a lot of code:
    # close file, chomp, die with error message.
error:
    close(FILE);
    chomp();
    die "Error parsing line $line_num: $_";
}

1;

