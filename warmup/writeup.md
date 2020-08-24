### DEFCON Qualifiers - Warmup

The first pwnable was indeed a warmup challenge, a 32-bit non-PIE binary, compiled with no canaries where the address of libc's *system* was leaked to us. The binary then requested user input with *fgets()* from stdin, of size 256 bytes. As expected for a warmup challenge, it was an easy-to-spot stack buffer overflow.

After smashing the stack, we take control of the return pointer, and point it to the system leak for the win. Straight-forward enough, huh? ;)