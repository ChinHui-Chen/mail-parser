#!/usr/bin/perl

use utf8 ;
binmode(STDOUT,':encoding(utf8)') ;

$str = "Yes先生" ;
&chip_chinese($str) ;

sub chip_chinese {
	my $str = $_[0] ;
	my $buff = "" ;

	for(my $i=0;$i<length $str;$i++){
			my $c = substr $str,$i,1 ;
			my $n = ord $c ;

			if($n>=0x4E00 && $n<=0x9FA5){
					if (!($buff eq "")){
						print $buff."\n" ;
						$buff = "" ;
					}
					print $c."\n" ;
			}else {
					$buff .= $c ;
			}
	}
}

