package Cpanel::Security::Advisor::Assessors::SSH;

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
use Whostmgr::Services::SSH::Config ();
use Cpanel::Logger();
use Cpanel::SafeFind();
use Cpanel::LoadFile ();
use Data::Dumper ();
use base 'Cpanel::Security::Advisor::Assessors';

sub version {
    return '1.01';
}

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_ssh_settings;
    $self->_check_for_ssh_version;
    $self->_check_for_libkeyutils;
    $self->_check_for_forkbomb;
}

sub _check_for_ssh_settings {
    my ($self) = @_;

    my $sshd_config = Whostmgr::Services::SSH::Config::get_config();

    if ( $sshd_config->{'PasswordAuthentication'} =~ m/yes/i || $sshd_config->{'ChallengeResponseAuthentication'} =~ m/yes/i ) {
        $self->add_bad_advice(
            'text'       => ['SSH password authentication is enabled.'],
            'suggestion' => [
                'Disable SSH password authentication in the “[output,url,_1,SSH Password Authorization Tweak,_2,_3]” area',
                $self->base_path('scripts2/tweaksshauth'),
                'target',
                '_blank'
            ],
        );
    }
    else {
        $self->add_good_advice(
            'text' => ['SSH password authentication is disabled.'],
        );

    }

    if ( $sshd_config->{'PermitRootLogin'} =~ m/yes/i || !$sshd_config->{'PermitRootLogin'} ) {
        $self->add_bad_advice(
            'text'       => ['SSH direct root logins are permitted.'],
            'suggestion' => [
                'Manually edit /etc/ssh/sshd_config and change PermitRootLogin to “no”, then restart SSH in the “[output,url,_1,Restart SSH,_2,_3]” area',
                $self->base_path('scripts/ressshd'),
                'target',
                '_blank'
            ],
        );
    }
    else {
        $self->add_good_advice(
            'text' => ['SSH direct root logins are disabled.'],
        );

    }

    if ( $sshd_config->{'Port'} = m/22/i || !$sshd_config->{'Port'} ) {
    $self->add_bad_advice(
       'text'   => ['SSHD is listening on port 22'],
       'suggestion' => [
        'It is recommended to have SSHD listening on a port other than 22.  Please check the "[output,url,_1,documentation for securing SSH,_2,_3]"',
        'http://docs.cpanel.net/twiki/bin/view/AllDocumentation/WHMDocs/SecureSSHConfig',
        'target',
        '_blank'
       ],
    );
    }
    else {
    $self->add_good_advice(
       'text' => ['SSH Port is not running on the default port (22)'],
    );
   }

   if ( $sshd_config->{'Protocol'} =~ m/1/i ) {
        $self->add_bad_advice(
            'text'              =>      ['SSHD is supporting protocol version 1'],
            'suggestion'        =>      [
                'It is recommended to have SSHD only support protocol version 2.  Please check the "[output,url,_1,documentation for securing SSH,_2,_3]"',
                'http://docs.cpanel.net/twiki/bin/view/AllDocumentation/WHMDocs/SecureSSHConfig',
                'target',
                '_blank'
           ],
        );
    }
    else {
        $self->add_good_advice(
           'text' => ['SSHD is only allowing protocol version 2'],
        );
   }

    my $mainip = $1 if Cpanel::LoadFile::loadfile('/etc/wwwacct.conf') =~ /ADDR (.*)/;
    my $listenip = $1 if Cpanel::LoadFile::loadfile('/etc/ssh/sshd_config') =~ /ListenAddress (.*)/;
    if ( $listenip eq '0.0.0.0' || $mainip eq $listenip || !$listenip ) {
            $self->add_bad_advice(
                'text'              =>      ["SSHD is listening on either all bound IPs or the main shared IP of the server"],
                'suggestion'        =>      [
                    'It is strongly recommended that you do not use your main shared IP address for this value.  Please check the "[output,url,_1,documentation for securing SSH,_2,_3]"',
                    'http://docs.cpanel.net/twiki/bin/view/AllDocumentation/WHMDocs/SecureSSHConfig',
                    'target',
                    '_blank'
               ],
            );
    }
    else {
        $self->add_good_advice(
           'text' => ["SSH is not listening on all interfaces nor the main shared IP"],
        );
   }
}

   

sub _check_for_ssh_version {
    my ($self) = @_;
    my ( $latest_sshversion, $current_sshversion );

    my $installed_rpms = $self->get_installed_rpms();
    my $available_rpms = $self->get_available_rpms();

    my $current_sshversion = $installed_rpms->{'openssh-server'};
    my $latest_sshversion  = $available_rpms->{'openssh-server'};

    if ( length $current_sshversion && length $latest_sshversion ) {
        if ( $current_sshversion lt $latest_sshversion ) {
            $self->add_bad_advice(
                'text'       => ['Current SSH version is out of date.'],
                'suggestion' => [
                    'Update current system software in the "[output,url,_1,Update System Software,_2,_3]" area',
                    $self->base_path('scripts/dialog?dialog=updatesyssoftware'),
                    'target',
                    '_blank'
                ],
            );
        }
        else {
            $self->add_good_advice( 'text' => [ 'Current SSH version is up to date: ' . $current_sshversion ] );
        }
    }
    else {
        $self->add_warn_advice(
            'text'       => ['Unable to determine SSH version'],
            'suggestion' => ['Ensure that yum and rpm are working on your system.']
        );
    }

}

sub _check_for_libkeyutils {
    my ($self) = @_;
    Cpanel::SafeFind::find(
        {'wanted' => sub {
                if ( $File::Find::name =~ /libkeyutils.so/ ) {
            my $res = Cpanel::SafeRun::Simple::saferun( '/bin/rpm', '-qf', $File::Find::name );
                        if ($res =~ m/file.*is not owned by any package/) {
                            $self->add_bad_advice(
                                'text'          =>  ["$File::Find::name is not owned by any system packages. This indicates a possibly rooted server."],
                                'suggestion'    =>  [
                                    'Check the following to determine if this server is compromised "[output,url,_1,Determine your Systems Status,_2,_3]"',
                                    'http://docs.cpanel.net/twiki/bin/view/AllDocumentation/CompSystem',
                                   'target',
                                    '_blank'
                                ],
                            );
                        }
                        else {
                            $self->add_good_advice( 'text' => [ "$File::Find::name is owned by package $res"] );
                        }
                }
            }
        },
        "/lib", "/lib64"
    );
}  

sub _check_for_forkbomb {
    my ($self) = @_;
    
    my $profile = Cpanel::LoadFile::loadfile('/etc/profile') or die Cpanel::Logger::die("Could not open /etc/profile:  $!\n");
    if ( $profile =~ /cPanel Added Limit Protections -- BEGIN/ ) {
    $self->add_good_advice( 'text' => ["Fork Bomb Protection Enabled"] );
    }
   else {
    $self->add_bad_advice(
        'text'      =>  ["Fork Bomb Protection disabled!"],
        'suggestion'    =>  [
            'It is highly advised to enable "[output,url,_1,Fork Bomb Protection,_2,_3]"',
            $self->base_path('scripts2/modlimits'),
            'target',
            '_blank'
        ],
       );
   }
}

1;
