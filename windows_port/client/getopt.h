#ifndef _GETOPT_H_
#define _GETOPT_H_

extern char* optarg;
extern int optind;
extern int opterr;

char* OptArg();

int getopt(__in int argc,
             __in_ecount(argc) char argv[20][256],
             __in_bcount_z(oplen) char *opstring,
             __in int oplen);

#endif
