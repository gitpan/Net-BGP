use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::BGP',
    'ABSTRACT'		=> 'Object-oriented API to the BGP protocol',
    'AUTHOR'		=> 'Stephen J. Scheck <code@neurosphere.com>',
    'VERSION_FROM'	=> 'lib/Net/BGP.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
);
