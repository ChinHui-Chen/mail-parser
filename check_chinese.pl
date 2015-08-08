#!/usr/bin/perl 

use utf8 ;

binmode(STDOUT,':encoding(utf8)') ;

$str= "YesMAN先生" ;

print &check_chinese($str)."\n" ;

sub check_chinese {
	my $str = $_[0] ;

	for(my $i=0;$i<length $str;$i++){
			my $c = substr $str,$i,1 ;
			my $n = ord $c ;

			if($n>=0x4E00 && $n<=0x9FA5){
					return 1 ;
			}
	}
	return 0 ;
}
