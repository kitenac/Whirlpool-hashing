/*
    Input handling due Whirlpool requirements.
    - making 512 byte blocks
    - padding according to Merkle-Damgard
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h> // for files
#include <unistd.h> // for read(), fread() somehow doesn`t work
#include "memory_stuff.h" // to know file size



// ========= Stuff functions =====================================================


// make string from hex. ex: 0x1F ---> "1F" 
char* ASCIIfied_hex(__uint8_t* hex_data){
    char* tr = "0123456789ABCDEF"; // translate-table
    char* ASCIIfied=(char*)malloc(64*2);  // each byte represented by 2 chars in string, so double size  
    __uint8_t byte;
   
    for (int i=0; i<64;++i){
        byte = hex_data[i];
        ASCIIfied[i*2] = tr[byte/16];
        ASCIIfied[i*2+1] = tr[byte%16];
        //printf("\n%d | byte: %x ---> %c %c\n", i, byte, tr[byte/16], tr[byte%16]);
    }    
    return ASCIIfied;
}


// there`s no strrev in linux`s C, so add from net
// len - needs to be specifed for "raw" bytes with 0x00 (strlen thinks it`s end of string)
// len = 0 - for "regular" strings (strlen can calculate it`s length itself)
__uint8_t* strrev(__uint8_t* s, int len){
    int i, j, temp; 
    i=0;
    (len == 0) ? (j = strlen(s) - 1) : (j = len-1);  

    while(i < j) {
      temp = s[i];
      s[i++] = s[j];
      s[j--] = temp;
    }
    return s;
}

// print byte array as hex dump
void print_x(__uint8_t* byte_arr){
    for (int i = 0; i < 32; ++i) printf("%X ", byte_arr[i]); printf("\n");
}


void slice_x(__uint8_t* byte_arr, __uint64_t Limit){
    for (int i = 0; i < Limit; ++i) printf("%X ", byte_arr[i]); printf("\n");
}

// uses to print state-matix in hex 
void state_x(__uint8_t* byte_arr){
    for (int i = 0; i < 64; ++i) {printf("%X ", byte_arr[i]); if ((i+1)%8==0 && i!=0) printf("\n");} printf("\n");
}




// ======== Padding =============================================


// get 32 byted L for padding - half-block of "row 32 bytes" in little-endian: 
// inside it looks as: | 0 x 24 + L(8 bytes) |. PS L - 8 bytes, not all 32 - bc of uint64, 
// but L can represent 2^64 bits - it`s 2 305 843 Tb - so it`s preeety enough))))
// L - here length in bytes
__uint8_t* get_L(__uint64_t L){
    
    printf("size of PT = %u bytes (in hex: %llX)\n", L, L); // %llx - для вывода всех байт
    __uint64_t L_bits = L*8;
    printf("\nbut we need to write L (in bits) to end of padd: L = %u bits", L*8);

    // uint8 except char for working with row bytes 
    __uint8_t* L_32 = (__uint8_t*) calloc(32, sizeof(__uint8_t));  // 256 bits = 32 bytes zeroes
    
    
    memcpy(L_32, &L_bits, sizeof(L_bits));
    /*
     16-ричное представление: 0x 19 34
     Запишется - 19 34
     т.к. порядок чтения байтов: 19, 34. 19 - lsb - с него чтение начинается
     Чтобы получить исходное число - нужно перевернуть строку - получится 00 00...19 34
    */

    //printf("\n[Before reverse]\n");
    //print_x(L_32);

    L_32 = strrev(L_32, 32);
    printf("\n[Padding] L32 After  reverse:\n");
    print_x(L_32);
    return L_32;
}

// ----------------------------------------------------------

// PS Эта функция писалась уже после get_blocks() - как вспомогательная
// [+++] Padding 
// returns - pointer to PT`s blocks padded at the end
// !!! address of "blocks" here may change!
__uint8_t*  handle_padding(__uint64_t L, __uint64_t N, __uint8_t remainder, __uint8_t* blocks){
/* Merkle-Damgard padding:
        |512| - |512| - ... - | remainder + 1 + 0000...00 + L| . 
        remainder - last part from PT that may not fully fill 512-bit block (thats why we need padding) 
        L = 256 bits - length of original message - PT
    possible cases of padding`re listed bellow:
*/
     
    __uint8_t* L32 = get_L(L);       // L - as "raw" 32 bytes 
    __uint8_t* padding = blocks + L; // end of PT - start of padding (due indexing from 0)

    printf("remainder = %u bytes \n", remainder);

    // !!! ---> 0x80 = 1000 0000 - byte to write binary '1' and zeroes after

    // [+] 0. PT fills entire block
    // |remainder| - |1 + 0 x 31 + L|
    if (remainder == 0){
        blocks = (__uint8_t*) realloc(blocks, N*64 + 64); // add extra-block to previously allocated size
        padding = blocks + L; // if pointer changed after realloc
        memset(padding,     0x80, 1);
        memset(padding+1,   0x00, 31);
        memcpy(padding+32, L32,  32);
        return blocks;
    }
    // [+] 1. padding fits block
    // |remainder + 1 + 00...0 + L|
    else if (0 < remainder && remainder < 31){
        __uint8_t zeroes = 31-remainder; // 32-remainder-1
        memset(padding,     0x80, 1);
        memset(padding+1,   0x00, zeroes); 
        memcpy(padding+1+zeroes, L32,  32);
        return blocks;
    }

    // [+] 2. padding can`t fit block (L requires 32 bytes - 256 bits)
    // | remainder + 1 + 00..0 | - | 0000..00 + L |
    else if (remainder >= 31){
        __uint8_t zeroes = 95-remainder; // 64-remainder-1 (first block) + 32 (extra block`s zeroes)
        //printf("\n\n zeroes = %u \n", zeroes);
        blocks = (__uint8_t*) realloc(blocks, N*64 + 64); // add extra-block to previously allocated size
        padding = blocks + L; // if pointer changed after realloc
        memset(padding,     0x80, 1);
        memset(padding+1,   0x00, zeroes); 
        memcpy(padding+1+zeroes, L32,  32);
        return blocks;
    }


    // 3. remainder = 31 - padding completely fits without adding zeroes:  |remainder + 1 + L|, but zeroes must be, so:
    // |remainder + 1 + 0 x 32| - | 0 x 32 + L| - adding extra block
    // so that remainder is 64 - 32 - 1 = 31 bytes
    // *this case - is special case of else if above

    perror("Padding error");
}



__uint8_t* get_block_i(__uint64_t i, __uint8_t* blocks){
    return &blocks[64*i];
}


// 512 bits - 64 bytes bloks
// fl - supposed to be oppened in "rb" mode
// L_pad - length after padding - just allocated memory that inits here
// get blocks for files
__uint8_t* get_blocks(FILE* fl, __uint64_t* L_pad){
    __uint64_t L = know_fl_sz(fl);
    __uint64_t N = L/64;                    // ammount of 64-byte blocks to hold all the PT
    if (N*64 < L || L==0) N++;              // add block if L/64 is fractional to hold all PT.  L = 0 - special case for empty string "" - with length = 0
    
    __uint8_t remainder = 64 - (N*64 - L);
    if (remainder >= 31)   N++;       // add block if remainder doesn`t fit into 31 bytes (1 + 32 bytes required for padding ending)

    __uint8_t* blocks = (__uint8_t*) calloc(N, 64); // N 64-byted blocks. 64 bytes = 512 bits 

    fread(blocks, L, 1, fl);
    

    //__uint8_t* last_block = get_block_i(N-1, blocks);  // block that needs paddiong
    printf("[before paddig]\nsize of file: %u bytes. we need %u 64byted blocks\n", L, N);
    
    *L_pad = 64*N; // init L_pad given us from above
    blocks = handle_padding(L, N, remainder, blocks);
    
    return blocks;    
}


// get blocks for string
__uint8_t* get_blocks_4_str(char* string, __uint64_t* L_pad){
    __uint64_t L = strlen(string);
    __uint64_t N = L/64;                    // ammount of 64-byte blocks to hold all the PT
    if (N*64 < L || L==0) N++;              // add block if L/64 is fractional to hold all PT.  L = 0 - special case for empty string "" - with length = 0
    
    __uint8_t remainder = 64 - (N*64 - L);
    if (remainder >= 31)   N++;       // add block if remainder doesn`t fit into 30 bytes (1('0x1') + 1 ('0x0' - required at least 1 zero) + 32 bytes required for padding ending)

    __uint8_t* blocks = (__uint8_t*) calloc(N, 64); // N 64-byted blocks. 64 bytes = 512 bits 
    memcpy(blocks, string, L);
    

    //__uint8_t* last_block = get_block_i(N-1, blocks);  // block that needs paddiong
    printf("[before paddig]\nsize of string: %u bytes. we need %u 64byted blocks\n", L, N);
    
    *L_pad = 64*N; // init L_pad given us from above
    blocks = handle_padding(L, N, remainder, blocks);

    // ------ Test padding for small(1-3 blocks) PT ---------
    //printf("\nThree first blocks after padding PT:\n");
    //state_x(get_block_i(0, blocks));    
    //state_x(get_block_i(1, blocks));
    //state_x(get_block_i(2, blocks));

    return blocks;    
}




