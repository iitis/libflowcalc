libflowcalc
===========

libflowcalc is a C library that supports conversion of raw PCAP files into flow statistics in ARFF
file format, readable by WEKA. See example.c to see example of how it can be applied.

For traffic trace file handling and flow management, it employs the WAND libtrace [1] and
libflowmanager [2] libraries.

Be sure to check-out flowcalc [3], which is probably much easier than direct libflowcalc.

1. http://research.wand.net.nz/software/libtrace.php
2. http://research.wand.net.nz/software/libflowmanager.php
3. http://mutrics.iitis.pl/flowcalc
