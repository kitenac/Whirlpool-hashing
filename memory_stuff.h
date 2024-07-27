/*
    Some memory allocation and file handling stuff
*/

#include <stdio.h>  // for files
#include <stdlib.h> // for u_int_t



// [+] tested. get File size 
// [TODO] make file_sz var 256 bit - as Whirlpool`s padding`s parametr L grants   
__uint64_t know_fl_sz(FILE* file){
    __uint64_t file_sz;    // File size
    if (file != NULL) {
     fseek(file, 0L, SEEK_END); 
     file_sz = ftell(file);

     fseek(file, 0L, SEEK_SET);   // return file pointer to start
    }
    return file_sz;
}
// вообще L из паддинга = 256 бит, так что и размер по-хорошему должен у file_sz 256 бит быть, а не 64,
// но 2^64 байт ~ 18,4 * 10^6 Tb - тоже неплохо)))







