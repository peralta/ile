#!/usr/bin/perl
# I Love Email - A notifier of the status of your mailbox for jabber
# Find it at: http://ile.jabberstudio.org
# Author:
# luis peralta / jaxp - peralta @ aditel . org
# http://spisa.act.uji.es/~peralta
# JID: al019409@mi.uji.es


use Net::Jabber qw(Component);
use XML::Simple;
use Net::POP3;
use Net::IMAP::Simple;
use DB_File;

# signal handling
$SIG{HUP} = \&Stop;
$SIG{KILL} = \&Stop;
$SIG{TERM} = \&Stop;
$SIG{INT} = \&Stop;
$SIG{ALRM} = \&get_mail;

my $config;
my $con;

# constants
use constant VERSION => "0.4";
use constant EXPIRETIME => 1800;

### DB tied
my %users;
my %passwords;
my %hosts;
my %types;
my %notifyxa;
my %notifydnd;
my %urls;

### Dinamically filled
my %laststat;
my %avail;

##### Init
sub load_config {
	print " - config\n";
	$config = XMLin("ile.xml");
}

# jsconnect - Sets up callbacks and connects to the jabber server
sub js_connect {
	print " - connecting to [$config->{'jabber'}->{'server'}]\n";
	$con = new Net::Jabber::Component(	debugfile	=>$config->{'debug'}->{'file'}, 
						debuglevel	=>$config->{'debug'}->{'level'},
					 );

	$con->Info(	name	=>	"ILE",
			version	=>	VERSION);

	$con->SetCallBacks(	onconnect	=> 	\&send_probes);

	$con->SetPresenceCallBacks(	available 	=>	\&presence_avail,
					unavailable	=>	\&presence_unavail,
				   );

	$con->DefineNamespace(	xmlns	=>	'vcard-temp',
				type	=>	'Query',
				functions=>	[
						 {
						   name	=> 'FN',
						   Get	=> 'FN',
						   Set	=> ['scalar', 'FN'],
						   Defined=> 'FN',
						   Hash	=> 'child-data',
						 },
						 {
						   name	=> 'DESC',
						   Get	=> 'DESC',
						   Set	=> ['scalar', 'DESC'],
						   Defined=> 'DESC',
						   Hash	=> 'child-data',
						 },
						 {
						   name	=> 'URL',
						   Get	=> 'URL',
						   Set	=> ['scalar', 'URL'],
						   Defined=> 'URL',
						   Hash	=> 'child-data',
						 },
						 {
						   name	=> 'JABBERID',
						   Get	=> 'JABBERID',
						   Set	=> ['scalar', 'JABBERID'],
						   Defined=> 'JABBERID',
						   Hash	=> 'child-data',
						 },
						 { name	=> 'Vcard',
						   Get	=> '__netjabber__:master',
						   Set	=> ["master"],
						 },
						],
			     );

	$con->SetIQCallBacks(	"vcard-temp"	=>	{ get	=> \&vcard_get_cb, },
				"jabber:iq:register" =>	{
								get=>\&iqRegisterGetCB,
								set=>\&iqRegisterSetCB,
                                                 	},
				"jabber:iq:browse"   =>	{
								get=>\&iqBrowseGetCB,
							},
			    );


	$con->Execute(	hostname	=>	$config->{'jabber'}->{'server'},
			port		=>	$config->{'jabber'}->{'port'},
			secret		=>	$config->{'jabber'}->{'secret'},
			componentname	=>	$config->{'jabber'}->{'service'},
		     );

	die "can't connect to jabber server" unless $con->Connected();
}


# db_init - ties the hashes with user info to files
sub db_init {
	tie (%users, 'DB_File', $config->{'files'}->{'users'}) 
		or die ("Cannot tie to " . $config->{'files'}->{'users'} ."!\n");
	tie (%passwords, 'DB_File', $config->{'files'}->{'passwords'}) 
		or die ("Cannot tie to " . $config->{'files'}->{'passwords'} ."!\n");
	tie (%hosts, 'DB_File', $config->{'files'}->{'hosts'}) 
		or die ("Cannot tie to " . $config->{'files'}->{'hosts'} ."!\n");
	tie (%types, 'DB_File', $config->{'files'}->{'types'}) 
		or die ("Cannot tie to " . $config->{'files'}->{'types'} ."!\n");
	tie (%notifyxa, 'DB_File', $config->{'files'}->{'notifyxa'}) 
		or die ("Cannot tie to " . $config->{'files'}->{'notifyxa'} ."!\n");
	tie (%notifydnd, 'DB_File', $config->{'files'}->{'notifydnd'}) 
		or die ("Cannot tie to " . $config->{'files'}->{'notifydnd'} ."!\n");
	tie (%urls, 'DB_File', $config->{'files'}->{'urls'}) 
		or die ("Cannot tie to " . $config->{'files'}->{'urls'} ."!\n");
}

# Stop - sends unavail presence, disconnects from the server, unties hashes
sub Stop {
	print " - Sending unavailable status\n";
	send_unavail();
	print "Exiting...\n";
	print " - Closing Jabber Connection\n";
	$con->Disconnect();
	print " - Untieing hashes\n";
	untie %users;
	untie %passwords;
	untie %hosts;
	untie %types;
	untie %notifyxa;
	untie %notifydnd;
	untie %urls;
	exit(0);
}

	
##### Jabber core

# iqRegisterGetCB - handles iq:register gets.
sub iqRegisterGetCB {
	my ($sid, $iq) = @_;

	my %fields;

	my $fromJID = $iq->GetFrom("jid");
	$fromJID = $fromJID->GetJID("base");
	
	# check if the user is already registered
	if (defined($users{$fromJID})) {
		$fields{'user'} = $users{$fromJID};
		$fields{'pass'} = $passwords{$fromJID};
		$fields{'host'} = $hosts{$fromJID};
		$fields{'type'} = $types{$fromJID};
		$fields{'notifyxa'} = $notifyxa{$fromJID};
		$fields{'notifydnd'} = $notifydnd{$fromJID};
		$fields{'url'} = $urls{$fromJID};
	}

	my $iqReply = $iq->Reply(type=>"result");
	my $iqReplyQuery = $iqReply->NewQuery("jabber:iq:register");
	$iqReplyQuery->SetRegister(	instructions	=>	$config->{'form'}->{$lang}->{'instructions'},
					user		=>	$fields{'user'},
					pass		=>	$fields{'pass'},
					host		=>	$fields{'host'},
					type		=>	$fields{'type'},
				  );

	$iqReplyQuery->SetRegistered() if exists($fields{user});

	$registerUser->RemoveValue();
	$registerUser->SetValue($fields{'user'});
	$registerPass->RemoveValue();
	$registerPass->SetValue($fields{'pass'});
	$registerHost->RemoveValue();
	$registerHost->SetValue($fields{'host'});
	$registerType->RemoveValue();
	$registerType->SetValue($fields{'type'});
	$registerNotXA->RemoveValue();
	$registerNotXA->SetValue($fields{'notifyxa'});
	$registerNotDND->RemoveValue();
	$registerNotDND->SetValue($fields{'notifydnd'});
	$registerUrl->RemoveValue();
	$registerUrl->SetValue($fields{'url'});

	$iqReplyQuery->AddX($registerForm);
	$con->Send($iqReply);
}

# iqRegisterSetCB - handles iq:register sets.
sub iqRegisterSetCB {
	my ($sid, $iq) = @_;

	my $fromJID = $iq->GetFrom("jid");
	$fromJID = $fromJID->GetJID("base");
	my $query = $iq->GetQuery();

	my $iqReply = $iq->Reply(type=>"result");
	my $iqReplyQuery = $iqReply->NewQuery("jabber:iq:register");

	# <remove/> ?
	if ($query->DefinedRemove()) {
		delete($users{$fromJID});
		delete($passwords{$fromJID});
		delete($hosts{$fromJID});
		delete($types{$fromJID});
		delete($notifyxa{$fromJID});
		delete($notifydnd{$fromJID});
		delete($urls{$fromJID});
		$con->Send($iqReply);
		return;
	}

	my @xData = $query->GetX("jabber:x:data");
	my %fields;
	if ($#xData > -1)
	{
		$fields{'user'} = "";
		$fields{'pass'} = "";
		$fields{'host'} = "";
		$fields{'type'} = "";
		$fields{'notifyxa'} = "";
		$fields{'notifydnd'} = "";
		$fields{'url'} = "";
		foreach my $field ($xData[0]->GetFields()) {
			$fields{$field->GetVar()} = $field->GetValue();
		}
	}

	$users{$fromJID} = $fields{'user'};
	$passwords{$fromJID} = $fields{'pass'};
	$hosts{$fromJID} = $fields{'host'};
	$types{$fromJID} = $fields{'type'};
	$notifyxa{$fromJID} = $fields{'notifyxa'};
	$notifydnd{$fromJID} = $fields{'notifydnd'};
	$urls{$fromJID} = $fields{'url'};

	$con->Send($iqReply);
	$con->PresenceSend(	to	=>	$fromJID,
				from	=>	$config->{'jabber'}->{'service'},
				type	=>	"subscribe",
			  );

}

# iqBrowseGetCB - Handles browse queries to the agent
sub iqBrowseGetCB {
	my ($sid, $iq) = @_;
	my $iqReply = $iq->Reply(type=>"result");
	my $iqReplyQuery = $iqReply->NewQuery("jabber:iq:browse");
	
	$iqReplyQuery->SetBrowse(NS	=>	[ 'jabber:iq:register',
						  'jabber:iq:time',
						  'jabber:iq:version',
						  'jabber:iq:last', ],
				Jid	=>	$config->{'jabber'}->{'service'},
				Name	=>	'ILE',
				Type	=>	'notice',
				Category=>	'headline',
			);

	$con->Send($iqReply);
}

# presence_avail - handles available presences of the users
sub presence_avail {
	my ($sid, $presence) = @_;

	my $fromJID = $presence->GetFrom("jid");
	$fromJID = $fromJID->GetJID("base");

	my $reply;

	if (not defined($users{$fromJID})) {
		$reply = $presence->Reply(type=>'unsubscribe');
	} else {
		$avail{$fromJID} = 1;

		# N::J intelligent presence DB
		$con->PresenceDBParse($presence);
		$reply = $presence->Reply(type=>'available', status=>'OK');
	}

	$con->Send($reply);
}

# presence_unavail - handles unavailable presences of the users
sub presence_unavail {
	my ($sid, $presence) = @_;

	my $fromJID = $presence->GetFrom("jid");
	$fromJID = $fromJID->GetJID("base");

	# N::J intelligent presence DB
	my $p = $con->PresenceDBParse($presence);

	if ($p->GetType() eq 'unavailable') {
		delete($avail{$fromJID});
		delete($laststat{$fromJID});
	}
}

# send_probes - sends presence probes to every user
sub send_probes {
	foreach my $jid (keys %users) {
		$con->PresenceSend(	to	=>	$jid,
					from	=>	$config->{'jabber'}->{'service'},
					type	=>	"probe",
				  );

	}
}

# send_unavail - sends unavailable presence to every available user
sub send_unavail {
	foreach my $jid (keys %avail) {
		$con->PresenceSend(	to	=>	$jid,
					from	=>	$config->{'jabber'}->{'service'},
					type	=>	"unavailable",
		);
	}
}

##### Mail core

# get_sum - gets mail status for a user
sub get_sum {
	my $jid = shift;

	print "Checking mail for $jid\n";
	
	my $pid = open(JA, "-|");
	
	if (not $pid) {
		# child
		if ($types{$jid} eq "pop") {
			my $pop3 = Net::POP3->new($hosts{$jid}, Timeout => $config->{'mail'}->{'timeout'});
			if (defined($pop3)) {
				if(defined($pop3->apop($users{$jid}, $passwords{$jid})) 
					or defined($pop3->login($users{$jid}, $passwords{$jid})) ) {
					my ($num, $size) = $pop3->popstat;
					print $num;
				} else {
					print "-1";
				}
			} else {
				print "-1";
			}
		} else {
			my $imapc = Net::IMAP::Simple->new($hosts{$jid});
			if (defined($imapc)) {
				if( defined($imapc->login($users{$jid}, $passwords{$jid}))) {
					my $num = $imapc->select('INBOX');
					print $num;
				} else {
					print "-1";
				}
			} else {
				print "-1";
			}
		}
		exit;
	} else {
		# parent
		my $line = <JA>;
		if ($line == -1) {
		# some error produced
			my $msg = new Net::Jabber::Message();
			my $body = $config->{'form'}->{$lang}->{'errorcheck'};
			$body =~ s/ACCOUNT/$users{$jid}\@$hosts{$jid} ($types{$jid})/;
			$msg->SetMessage(type	=>	'normal', 
					 to	=>	$jid,
					 from 	=>	$config->{'jabber'}->{'service'},
					 subject=> 	'ILE',
					 body	=>	$body,
					);
			my $xe = $msg->NewX("jabber:x:expire");
			$xe->SetSeconds(EXPIRETIME);
			$con->Send($msg);
		} else {
			if (not defined($laststat{$jid})) {
				$laststat{$jid} = $line;
			} elsif ($line > $laststat{$jid}) {
			# changes in the mailbox
				my $msg = new Net::Jabber::Message();
				my $num = $line - $laststat{$jid};
				my $body = $config->{'form'}->{$lang}->{'newmail'};
				$body =~ s/NUM/$num/;
				$body =~ s/CHECKINTERVAL/$config->{'mail'}->{'checkinterval'}/;
				$msg->SetMessage(type	=>	'normal', 
					 	 to	=>	$jid,
						 from 	=>	$config->{'jabber'}->{'service'},
						 subject=> 	'ILE',
						 body 	=> 	$body,
						);
				my $xe = $msg->NewX("jabber:x:expire");
				$xe->SetSeconds(EXPIRETIME);
				if (defined($urls{$jid})) {
					my $xoob = $msg->NewX("jabber:x:oob");
					my $desc = $config->{'form'}->{$lang}->{'webmail_login'};
					$desc =~ s/ACCOUNT/$users{$jid}\@$hosts{$jid}/;
					$xoob->SetDesc($desc);
					$xoob->SetURL($urls{$jid});
				}
				$con->Send($msg);
				$laststat{$jid} = $line;
			}
		}
		close(JA);
		{} until wait() == -1;
	}	

}

# calls get_sum for every available user
sub get_mail {
	foreach my $jid (keys %avail) {
		if (defined($users{$jid})) {
			my $pres = $con->PresenceDBQuery($jid);
			my $stat = $pres->GetShow();
			if (($notifyxa{$jid} == 0 and $stat eq 'xa') or
				($notifydnd{$jid} == 0 and $stat eq 'dnd')) {
				next;
			}
			get_sum($jid);
		}
	}
	alarm($config->{'mail'}->{'checkinterval'} * 60);
}


##### Helper funcs

# vcard_get_cb - handles vcard-temp ns
sub vcard_get_cb { 
	my ($sid, $iq) = @_;
	my $reply = $iq->Reply(type=>'result');
	my $replyQuery = $reply->GetQuery();
	$replyQuery->SetFN($config->{'jabber'}->{'vCard'}->{'FN'});
	$replyQuery->SetDESC($config->{'jabber'}->{'vCard'}->{'DESC'});
	$replyQuery->SetURL($config->{'jabber'}->{'vCard'}->{'URL'});
	$replyQuery->SetJABBERID($config->{'jabber'}->{'service'});
	$con->Send($reply);
}	


##### Main
print "Loading...\n";

load_config();
local $lang = $config->{'jabber'}->{'language'};

local $registerForm = new Net::Jabber::X();
$registerForm->SetXMLNS('jabber:x:data');
$registerForm->SetData(	instructions	=>	$config->{'form'}->{$lang}->{'instructions'},
			title		=>	$config->{'form'}->{$lang}->{'title'},
			type		=> 	"form",
		      );

$registerForm->AddField(	type	=>	'fixed',
				value	=>	$config->{'form'}->{$lang}->{'email_options'},
			);

local $registerUser = $registerForm->AddField(	type	=>	'text-single',
						var	=>	'user',
						label	=>	$config->{'form'}->{$lang}->{'user'},
					  );

local $registerPass = $registerForm->AddField(	type	=>	'text-private',
						var	=>	'pass',
						label	=>	$config->{'form'}->{$lang}->{'pass'},
					  );

local $registerHost = $registerForm->AddField(	type	=>	'text-single',
						var	=>	'host',
						label	=>	$config->{'form'}->{$lang}->{'host'},
					  );

local $registerType = $registerForm->AddField(	type	=>	'list-single',
						var	=>	'type',
						label	=>	$config->{'form'}->{$lang}->{'type'},
						desc	=>	$config->{'form'}->{$lang}->{'type'},
					  );

$registerType->AddOption(	label	=>	'POP',
				value	=>	'pop',
			);

$registerType->AddOption(	label	=>	'IMAP',
				value	=>	'imap',
			);

$registerForm->AddField(	type	=>	'fixed',
				value	=>	$config->{'form'}->{$lang}->{'notify_options'},
			);

local $registerNotXA = $registerForm->AddField(	type	=>	'boolean',
						var	=>	'notifyxa',
						label	=>	$config->{'form'}->{$lang}->{'notifyxa'},
					      );

local $registerNotDND = $registerForm->AddField(type	=>	'boolean',
						var	=>	'notifydnd',
						label	=>	$config->{'form'}->{$lang}->{'notifydnd'},
					      );

local $registerUrl = $registerForm->AddField(	type	=>	'text-single',
						var	=>	'url',
						label	=>	$config->{'form'}->{$lang}->{'webmail_url'},
					  );

$registerForm->AddField(	type	=>	'fixed',
				value	=>	$config->{'form'}->{$lang}->{'iledesc'},
			);

db_init();
alarm($config->{'mail'}->{'checkinterval'} * 60);
js_connect();
