# p-sandbox
A ptrace based sandbox. (PoC)

--------------------------------


This is a small sandbox to limit the number of allowed syscalls for a process.

There is no configuration file, you must edit the source itself...


## To compile :

$ gcc -o p-sandbox p-sandbox.c


## To run :

$ ./p-sandbox /sandboxed/process


## Author

-TOSH-