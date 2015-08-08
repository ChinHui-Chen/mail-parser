#!/usr/bin/perl 

use utf8 ;

binmode(STDOUT,':encoding(utf8)') ;

$pattern = shift @ARGV ;

$str= "YesMAN 先生" ;

$l = length $str ;

print $str."\n" ;
print $l."\n" ;
print "Pattern = $pattern\n" ;
print "有Match!\n" if ($str =~ /$pattern/) ;
