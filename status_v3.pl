#!/usr/bin/perl
use utf8 ;
use strict ;
use Mail::Box::Manager;
use File::MMagic;
use IO::Handle;
use MIME::Words qw(:all);
use Text::Iconv;
use POSIX qw(ceil floor);

# local configure
my $mask = "255.255.255.0" ;
my $size_interval = 10000 ;
my $size_detail = 10000 ; # below this size will show detail scale
my $attachments = "./attachment" ;
my $report_out = "./report" ;
my $subject_out = "./report_subject" ;
my $support_encoding = "./support_encoding" ;
my $relay_list = "./relay_list" ;

my $mbox = shift ;
my $sel = shift ;
my $normal = shift ;
my $mgr    = Mail::Box::Manager->new;
my $folder = $mgr->open(folder => $mbox , 
                         type => 'Mail::Box::MBox');

# default variable
my @relay ;
my @encodings ;
my @encodings_cache ;
my $total_mail =  $folder->messages ;
my $cur_mail ;
my $virus_num=0 ;
my %virus_size ;
my %virus_class ;
my %virus_ip ;
my %virus_ip_class ;
my %virus_ip_class2 ;
my %virus_domain ;
my %virus_attach ;
my %virus_attach_class ;
my @virus_attach_neq ;
my @virus_envlop_neq ;
my $virus_attach_count ;
my $virus_envlop_count ;
my %virus_encoding ;
my %virus_encoding_subject;
my %virus_encoding_attach;

my $count_v ;
my @plain_html ;

# program start
unlink  $subject_out ;

# load support encoding
open(FH,$support_encoding) ;
@encodings = <FH> ;
close FH ;

# load realy list
open(FH,$relay_list) ;
@relay = <FH> ;
close FH ;

# for each message
foreach my $m($folder->messages) {
	my $head = $m->head ;
	my $size = $m->size ;
	my $flag_detect = 0 ;
	$cur_mail = $m->seqnr ;

	if( $sel eq "virus" ) {
		my $flag=0;
		my @virus = $head->get('X-Amavis-Alert') ;
		foreach my $v(@virus){
			if( $v =~ /(.*), message contains virus: (.*)/i ){
				$flag=1;
			}
		}
		$flag_detect = 1 if ($flag) ;
		if($flag_detect){
			my @virus = $head->get('X-Amavis-Alert') ;
			foreach my $v(@virus){
				if( $v =~ /(.*), message contains virus: (.*)/i ){
					$virus_class{$1."_".$2}++ ;
				}	
			}
		}

	} elsif( $sel eq "spam" ){
		$flag_detect = 1 if( defined($m->get('X-Spam-Score')) ) ; 
	
		if($flag_detect){
			my $spam = $m->get('X-Spam-Score');
			($spam) = split(/\s/,$spam);
			$virus_class{ceil($spam)}++ ;
		}

	} elsif( $sel eq "banned"){
		my $flag=0;
		my @virus = $head->get('X-Amavis-Alert') ;
		foreach my $v(@virus){
			if( $v =~ /^BANNED/ ){
				$flag=1;
			}
		}
		$flag_detect = 1 if ($flag) ;

		if($flag_detect){
			my @virus = $head->get('X-Amavis-Alert') ;
			foreach my $v(@virus){
				if( $v =~ /^BANNED/ ){
					$virus_class{$v}++ ;
				}
			}
		}	

	} elsif( $sel eq "bad_header" ){
		my $flag=0;
		my @virus = $head->get('X-Amavis-Alert') ;
		foreach my $v(@virus){
			if( $v =~ /^BAD HEADER/ ){
				$flag=1;
			}
		}

		$flag_detect = 1 if ($flag);
	
		if($flag_detect){
			my @virus = $head->get('X-Amavis-Alert') ;
			foreach my $v(@virus){
				if( $v =~ /^BAD HEADER/ ){
					$virus_class{$v}++ ;
				}
			}
		}
	} else {
		print STDERR "invalid parament" ;
		exit ;
	}
	# print out all subject
	&print_out_subject( $cur_mail , $m , $flag_detect ) ;

	if($flag_detect){
		# get received ip , class_c
		my $received ;
		
		# if normal mail
		if($normal eq "normal"){
			my $i=0 ;
			my $flag=0 ;
			while(1){
				last unless(defined($head->get('Received' , $i))) ;

				$received = $head->get('Received' , $i) ;

				# find relay , flag =1 if find`
				foreach my $relay_site(@relay){
					chomp $relay_site ;
					if( $received =~ /by $relay_site/s && !($received =~ /from localhost \(localhost \[127\.0\.0\.1]\)/s) ){
						$flag = 1 ;
						last ;
					}
				}		
				$i++ ;		
			}
			$received="" if($flag==0) ;
		}else{
			$received = $head->get('Received' , 0) ; # get the top one
		}

		my $ip = &receive_filter($received) ;
		$virus_ip{$ip}++ ;

		$mask = "255.255.255.0" ;
		$virus_ip_class{ &mask_ip($ip) }++ ;
		$mask = "255.255.0.0" ;
		$virus_ip_class2{ &mask_ip($ip) }++ ;

		# get domain
		my $from = $m->get('From');
		my $domain = &domain_filter($from) ;
		$virus_domain{$domain}++ ;
		
		# attachment
		# detect plain/html
		$count_v=0;
		$plain_html[0]=0;
		$plain_html[1]=0;
		&show_attach($m,$flag_detect) ;
		# if only plain or html
		
		if($plain_html[0]==1 && $plain_html[1]==0 && $count_v==1){
			$virus_attach{"plain only"}++ ;
		}elsif($plain_html[0]==0 && $plain_html[1]==1 && $count_v==1){
			$virus_attach{"html only"}++ ;
		}elsif($plain_html[0]==1 && $plain_html[1]==1 && $count_v==2){
			$virus_attach{"plain+html"}++ ;
		}elsif($plain_html[0]+$plain_html[1] == $count_v){
			$virus_attach{"plain ".$plain_html[0]." html ".$plain_html[1]}++ ;	
		}else{
			$virus_attach{$count_v-$plain_html[0]-$plain_html[1]}++ ;
		}
		# envelope
		&check_envelope($m,$flag_detect);		
		
		#size
		if($size < $size_detail){
			$virus_size{ceil($size/($size_interval/10))*($size_interval/10)}++ ;
		}else{
			$virus_size{ceil($size/$size_interval)*$size_interval}++ ;
		}
		$virus_num++ ;
	}

	# temp save
	if($cur_mail+1 % 1000 == 0){
		&print_out ;
	}
}

&print_out ;
# end of program

sub print_out_subject{
	my $seq = shift ;
	my $m = shift ;
	my $flag_detect = shift ;
	my $sub = $m->subject ;	
	
	open FH , ">> $subject_out" ;

	if( $sub =~ /=\?(.*?)\?[Q|B]\?/i ){
		my $enc = $1 ;
		my $decoded = decode_mimewords($sub,);
		my $flag = 0 ;	

		#apply cache
		if( grep( /^$enc\n/i , @encodings_cache ) ){ # in cache
			$flag=1;
		}elsif ( grep( /^$enc\n/i , @encodings) ){   # not in cache , but in all
			push( @encodings_cache , uc($enc)."\n" ) ;
			$flag=1;
		}

		if($flag){
			# record subject encoding
			$virus_encoding_subject{lc($enc)}++ if($flag_detect) ;

			my $converter = Text::Iconv->new($enc, "UTF-8");
			$sub = $converter->convert($decoded);
		}else{
			# record subject encoding
			$virus_encoding_subject{"UNKNOWN Encoding"}++ if($flag_detect) ;
			print STDERR "unknow encoding ::$enc\n" ;
			$sub = $decoded ;
		}
	}else{
		# record subject encoding
		$virus_encoding_subject{"NO Encoding"}++ if($flag_detect) ;

		# decode anyway
		my $converter = Text::Iconv->new("BIG5", "UTF-8");
		$sub = $converter->convert($sub);
	}

	print FH "no.$seq ".$sub."\n" ;

	close FH ;
}

sub domain_filter{
	my $domain = shift ;
	my $result ;

	# fix domain 
	if( $domain =~ /(([A-Za-z0-9]+_+)|([A-Za-z0-9]+\-+)|([A-Za-z0-9]+\.+)|([A-Za-z0-9]+\++))*[A-Za-z0-9]+@(((\w+\-+)|(\w+\.))*\w{1,63}\.[a-zA-Z]{2,6})/)	     {
        	$result = $6 ;
	}else{
		$result = "invalid domain" ;
	}
	
	return $result; 
}

sub check_envelope{
	my $m = shift ;
	my $flag_detect = shift ;
	my $flag=0;

	my $env_from = $m->get('X-Envelope-From');	
	my $env_to = $m->get('X-Envelope-To');
	my $from = $m->get('From');
	my $to = $m->get('To') ;	

	($env_from) = ( $env_from =~ /<(.*?)>/ ) ;
	($env_to) = ( $env_to =~ /<(.*?)>/ ) ;

	if( !($from =~ /$env_from/) ){
		$flag=1;
		#push( @virus_envlop_neq , "$cur_mail\tFrom" ) if($flag_detect) ;
	}
	if( !($to =~ /$env_to/) ){
		$flag=1;
		#push( @virus_envlop_neq , "$cur_mail\tTo" ) if($flag_detect) ;
	}
	if($flag){
		$virus_envlop_count++ ;
	}
}

sub show_attach{
	my $msg = shift ;
	my $flag_detect = shift ;
	my $type = $msg->body->mimeType ;
	
	if($type eq ""){
		return ;
	}

	# if not multipart , is single
	if(!($type =~ /multipart/)){
		# get file name
		my $attachment = $msg->body->dispositionFilename($attachments);
		#print STDERR $attachment."\n" ;	
		
		# record attach encoding
		if($attachment =~ /\?(.*?)\?[Q|B]\?/i ){
			$virus_encoding_attach{lc($1)}++  ;
		}else{
			$virus_encoding_attach{"NO Encoding"}++ ;
		}

		unless(-f $attachment) {
			open(FH, '>', $attachment)
				or die "ERROR: cannot write attachment to $attachment: $!\n";
			$msg->decoded->print(\*FH);
			close(FH)
				or die "ERROR: writing to $attachment: $!\n";
		}
		# detect extension
		my $mm = new File::MMagic ;
		my $ext = $mm->checktype_filename($attachment);
		if( $ext ne $type ){
			$virus_attach_count++ ;
			#push(@virus_attach_neq , "$cur_mail\tType: $type\n\tFile: $ext") if($flag_detect) ;
		}
		unlink $attachment ;
		
		$virus_attach_class{$type}++ ;

		# if not text/plain && text/html , is attachment	
		#if( $type ne "text/plain" && $type ne "text/html" ){
		$plain_html[0]++ if($type eq "text/plain") ;
		$plain_html[1]++ if($type eq "text/html") ;
		$count_v++ ;
		#	return ;
		#}else{ # is plain
		# get charset
		my $charset = $msg->body->charset ;
		$virus_encoding{lc($charset)}++ ;
	
		return ; 
		#}
	}else{
		foreach my $part ($msg->parts){
			&show_attach($part,$flag_detect) ;
		}
	}
}

sub virus_filter{
	my $virus = shift ;


	if( $virus =~ /^BAD HEADER/ ){
		$virus = "BAD_HEADER" ;
	}

	if( $virus =~ /^BANNED/ ){
		$virus = "BANNED" ;
	}

	return $virus ;	
}

sub receive_filter{
	my $rec = shift ;
	my $ip = "" ;
	# parse host+ip
	if( $rec =~ /(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))/ ) {
		$ip = $1 ;
	}else{
		$ip = "noip" ;
		print STDERR "No ip:: $cur_mail $rec\n" ;
	}

	return $ip ;
=c
	if( $rec =~ /(.*?) by /s ){
		my $tmp = $1 ;
		if( $tmp =~ /([\d]+\.[\d]+\.[\d]+\.[\d]+)/ ){
			$ip = $1 ;
		}else{
			$ip = "noip" ;
			print "NO IP ::".$rec."\n" ;
		}
	}

	if($ip eq ""){
		$ip = "noip" ;
		print "NO IPPP ::".$rec."\n" ;
	}
	return $ip ;
=cut
}

sub mask_ip{
	my $ip = shift ;
	my $class_c ;
	# prevent failure
	return $ip if($ip eq "noip") ;
	# get mask
	$mask =~ /([\d]+)\.([\d]+)\.([\d]+)\.([\d]+)/ ;
	my @m = ($1,$2,$3,$4) ;
	# get ip
	$ip =~ /([\d]+)\.([\d]+)\.([\d]+)\.([\d]+)/ ;
	my @i = ($1,$2,$3,$4) ;
	# go mask
	for(my $k=0;$k<4;$k++){
		 $class_c .= int($i[$k]) & int($m[$k]) ;
		 last if($k==3) ;
		 $class_c .= "." ;
	}
	
	return $class_c ;
}

sub print_out{
	
	open FH , "> $report_out"."_$sel" ;
	STDOUT->fdopen( \*FH, 'w' ) or die $!;

	print "Total messages: $total_mail\n" ;
	print "$sel messages: $virus_num\n" ;
	
	print "\nThe distribution of $sel\n" ;
if($sel eq "spam"){
	foreach my $keys(sort{$a <=> $b} keys %virus_class){
		print "$keys = $virus_class{$keys}\n" ;
	}
}else{
	foreach my $keys( keys %virus_class){
		print "$keys = $virus_class{$keys}\n" ;
	}	
}
	print "\nThe distribution of attachment number\n";
	foreach my $keys(sort {$a <=> $b} keys %virus_attach){
		print "$keys attachments = $virus_attach{$keys}\n" ;
	}

	print "\nThe distribution of attachment Content-Type\n" ;
	
	foreach my $keys(sort {$a <=> $b} keys %virus_attach_class){
		print "$keys = $virus_attach_class{$keys}\n" ;
	}

	print "\nAttachment equals Content-Type?\n" ;
	
	if($virus_attach_count==0){
		print  "All equal\n" ;
	}else{
		print "diff: $virus_attach_count\n" ;
		foreach my $v (@virus_attach_neq) {
			print $v."\n" ; 
		}
	}

	print "\nThe distribution of email size\n" ;
	foreach my $keys(sort {$a <=> $b} keys %virus_size){
		print "$keys sizes = $virus_size{$keys}\n" ;
	}	

	print "\nThe distribution of From IP\n" ;
	foreach my $keys(sort {$a <=> $b} keys %virus_ip){
		print "$keys = $virus_ip{$keys}\n" ;
	}
	print "\nThe distribution of From IP with Class C : 255.255.255.0\n" ;
	foreach my $keys(sort {$a <=> $b} keys %virus_ip_class){
		print "$keys = $virus_ip_class{$keys}\n" ;
	}
	
	print "\nThe distribution of From IP with Class B : 255.255.0.0\n" ;
	foreach my $keys(sort {$a <=> $b} keys %virus_ip_class2){
		print "$keys = $virus_ip_class2{$keys}\n" ;
	}
	
	print "\nThe distribution of From Domain\n" ;
	foreach my $keys(sort {$a <=> $b} keys %virus_domain){
		print "$keys = $virus_domain{$keys}\n" ;
	}

	print "\nThe distribution of mime encoding\n" ;
	foreach my $keys(sort {$a <=> $b} keys %virus_encoding){
		print "$keys = $virus_encoding{$keys}\n" ;
	}

	print "\nThe distribution of subject encoding*\n" ;
	foreach my $keys(sort {$a <=> $b} keys %virus_encoding_subject){
		print "$keys = $virus_encoding_subject{$keys}\n" ;
	}
	
	print "\nThe distribution of attachment encoding\n" ;
	foreach my $keys(sort {$a <=> $b} keys %virus_encoding_attach){
		print "$keys = $virus_encoding_attach{$keys}\n" ;
	}
		
	
	print "\nCheck Envelope ?\n" ;
	
	if($virus_envlop_count==0){
		print  "All equal\n" ;
	}else{
		print "diff: $virus_envlop_count\n" ;
	}

	close FH ;
}
