package Cpanel::Security::Advisor::Assessors::Mail;

# Copyright (c) 2013, cPanel, Inc.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use Cpanel::Version  ();
use Cpanel::LoadFile ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;
    $self->_check_headers;
    $self->_check_restrictions;
    $self->_check_spamassassin;
    $self->_check_spam_prevention;
    return 1;
}

sub _check_headers {
    my ($self) = @_;
    my $cpanelconf = Cpanel::LoadFile::loadfile('/var/cpanel/cpanel.config');
    if ( Cpanel::LoadFile::loadfile('/etc/exim.conf') =~ /control = dkim_disable_verify/ ) {
	$self->add_warn_advice(
	    'text'		=>	['DKIM checking is disabled.'],
	    'suggestion'	=>	[
		'DKIM verification for incoming messages is disabled.  This is recommended to verify senders of emails, and will reduce spam.  This can be enabled in the "[output,url,_1,Exim Configuration Manager,_2,_3]"',
		$self->base_path('scripts2/displayeximconfforedit'),
		'target',
		'_blank'
	    ]
        );
    }
    else {
	$self->add_good_advice( 'text' => ['Incoming DKIM Verification is enabled'] );
    }

    if ( $cpanelconf =~ /eximmailtrap=1/ ) {
	$self->add_warn_advice(
	    'text'		=>	['Tracking email origins via X-Source headers is disabled'],
	    'suggestion'	=>	[
		'It is recommended to enable this feature to assist mail servers in tracking origins of emails.  This can be enabled in "[output,url,_1,Tweak Settings->Mail,_2,_3]"',
	   	$self->base_path('scripts2/tweaksettings#tab_Mail'),
	   	'target',
	   	'_blank'
	    ]
	);
    } 
    else {
	$self->add_good_advice( 'text' => ['X-Source tracking is enabled'] );
    }
    
    if ( $cpanelconf =~ /popbeforesmtpsenders=1/ ) {
	$self->add_bad_advice (
	    'text'		=>	['X-PopBeforeSMTP header for mail sent via POP-before-SMTP is enabled'],
	    'suggestion'	=>	[
		'This measure may compromise the privacy of your users by allowing authentication from alternate IP addresses.  It is not recommended to enable this unless absolutely necessary.  You can disable this in "[output,url,_1,Tweak Settings -> Mail,_2,_3]"',
	    	$self->base_path('scripts2/tweaksettings#tab_Mail'),
	    	'target',
	    	'_blank'
	    ]
	);
    }
    else {
	$self->add_good_advice( 'text' => ['Pop Before SMTP is disabled'] );
    }
    return 1;
}

sub _check_restrictions {
    # Check 'Restrict outgoing to root, exim, and mailman (FKA SMTP Tweak)'
    # Check 'Prevent "nobody" from sending mail'
    # Check and advise on Max hourly emails per domain
      # Warn on unlimited or > 100k
    # Max % of failed / deffered messages per domain/hour
}

sub _check_spamassassin {
    # Check to see if SA is enabled
    # Check to see if SpamAssassin has been recently
}

sub _check_spam_prevention{
    # cPanel default RBL Lists
    # Check for outgoing SpamAssassin routing
}

1;