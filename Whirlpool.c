#include <stdio.h>
#include <stdlib.h>     // for u_int_t
#include <string.h>     //for memset

#include "input_handle.h" 
#include "round_functions.h"



// get i-th round constant  
__uint8_t* rC_i(int i, __uint8_t* rC){
return rC + (i-1)*64;
}




// operation per one block of data
__uint8_t* whirlpool_core(__uint8_t* block, __uint8_t* H_prev, __uint8_t* rC){

    // i-th round key and constant
    __uint8_t* K_i;
    __uint8_t* const_i;        

    // 1 + 10 round-keys
    __uint8_t* Keys = (__uint8_t*) malloc(64*11); 
    memcpy(Keys, H_prev, 64);   //K0 - just H_prev

    
    __uint8_t* Key_i(int i){    // get key[i]
        return Keys + i*64;
    }

    // ---- KDF + Transform | each iteration gen K_i and use it to transform input block -----
    // [+++]
    
    sigma_f(block, H_prev);     // pre-round transform: xor with (K0 = H_prev)
    for(int i = 1; i<=10; ++i){
        // ------ KDF -------------------
        const_i = rC_i(i, rC);  // taking pre-counted i-th round constant 
        K_i = Key_i(i);         // get {address} for i-th key

        // We need K_i-1 as intermediate val - see comments near "return" in rho() 
        memcpy(K_i, Key_i(i-1), 64);   // get intermediate {value} of i-th key: coppy (i-1)-th key into i-th key 
        rho_f(K_i, const_i);           // adress stays, value - changes
        
        
        /*// ---- test: print sub-keys ----
        printf("\n%d-th round Key:\n", i);
        state_x(K_i);
        // -------------------------------*/

        // ------ transform block by obtained K_i ---------
        rho_f(block, K_i);
    }

    free(Keys);
    return block;
}



/* Whirlpool hash function:
  algo:
                           block_i------------|
                             |                |
    ... ---> H_i ---> |whirlpool_core| ----->(+)--> H_i+1 ---> ... H_n
              |                               |
              |------------"H_prev"-----------|

    whirlpool_core - "whirlpool encryption function"

  params:
    [Plain_Text_blocks] - PT cutten into bloks + padded - use get_blocks()
    [L_pad] : length of PADDED Plain_Text 
*/
__uint8_t* Whirlpool(__uint8_t* Plain_Text_blocks, __uint64_t L_pad){

    // Hash algorithm corrupts passed-in data, so copy initial PT into working buffer 
    __uint8_t* PT = (__uint8_t*) malloc(L_pad);               // working-buffer, where Plain Text corrupts into hash
    memcpy(PT, Plain_Text_blocks, L_pad);        // coppy to buffer

    // Rename pointer to original, not corrupted plain text 
    __uint8_t* Clear_blocks = Plain_Text_blocks; 

    // ------ Precount Round Constants -----
    // [Optimization] 
    // [+++]
    __uint8_t* rC = (__uint8_t*) malloc(640); // выделяем память под все 10 матриц
    
    /* code for tweaked S-box
    __uint8_t* S_row = malloc(8);  // 8 bytes in a row from S
    for (int k=0;k<8;++k)
            memset(S_row+k, S_box(i*8+k), 1);*/

    for(int i=0; i<10;++i){
        memcpy(rC + i*64, &S_box[8*i], 8); // очередные 8 байт из S_box копируем в 0-ую строку rC_i
        
        /*// ----- testing: showing values of rC_i ---- 
        printf("\n%d-th round constant:\n", i+1);
        state_x(rC + i*64);*/
    }


    // ----- Chaining hash-blocks Core - highest Whirlpool abstraction ----
    __uint8_t* i_block;             // i_block - proceeding block - will no longer contain PT, but pre-hash value
    __uint8_t* H_prev;              // H_prev - previous hash
    __uint8_t* H_i;                 // H_i - intermediate hash

    __uint64_t N = L_pad / 64;      // N - ammount of blocks that has PT    
    __uint8_t* H_0 = (__uint8_t*) calloc(64, 1); // H_0 - ini_vector of zeroes for Whirlpool
    H_prev = H_0;

    for (__uint64_t i = 0; i<N; ++i){
        i_block = get_block_i(i, PT);
        H_i = whirlpool_core(i_block, H_prev, rC);  
        
        // Зацепление блоков, по сути
        // XORing: whirlpool_core`s output with H_prev and i-th block before proceeding - Clear_block_i
        sigma_f(H_i, H_prev);
        sigma_f(H_i, get_block_i(i, Clear_blocks));

        H_prev = H_i;   // H_prev is H_i - for next round
    }


    __uint8_t* hash = (__uint8_t*) malloc(64);
    memcpy(hash, H_i,64);

    // [Optimization] 
    free(PT);  // PT(working buffer) gave us H_i - and no longer required
    free(rC);
    free(H_0);

    return hash;  // raw bytes. can be reflected to string by ASCIIfied_hex() from input_handle.h
}







// ---- Eazy interfaces to get Whirpool hash (~Manager functions)-----
// here we cut PT(as string or file) into 64-byted blocks + pad (Merkle-Damgard) 


// for file input
__uint8_t* Whirpool_4fl(FILE* file){
    __uint64_t L_pad;                               // length after padding - inits by calling get_blocks()
    __uint8_t* blocks = get_blocks(file, &L_pad);   // getting blocks for Whirlpool
    
    return Whirlpool(blocks, L_pad);
}


// for sting input
__uint8_t* Whirpool_4str(char* string){
    __uint64_t L_pad; 
    __uint8_t* blocks = get_blocks_4_str(string, &L_pad);
    
    // ----- Show padded PT
    printf("\n[Length of PT after padding = %lu] Padded PT is: \n", L_pad);
    slice_x(blocks, L_pad);

    return Whirlpool(blocks, L_pad);
}





int main(){

// drug.jpg darkness.jpg M51_Whirlpool.jpg Test_scentence.wtf  71_3dwall.tar
    FILE* file = fopen("M51_Whirlpool.jpg", "rb");
    if (file == NULL) { printf("Error opening file\n"); return 1;}


    // ---------- Test get_L() - See how 8-byted integer converts into 32-byted byte-array in "good"-endian
    //__uint64_t L = 0x01af00cc12d4afee;         
    //__uint8_t* L_32 = get_L(L);
    //print_x(L_32);
    // после использования надо почистить
    //free(L_32);


    // ---------- Get file size ----------
    //__uint64_t L = know_fl_sz(file);
    

    // ---------- Whirlpool hash for file and for string:
    
    // file
    __uint8_t* hash = Whirpool_4fl(file);
    printf("\n -Wow, we`ve got Whirlpool hash for file: \n");
    state_x(hash);
    char* as_str = ASCIIfied_hex(hash);
    printf("\nASCIIfied hex:\n%s\n\n\n", as_str);
    
    printf("\n\n-----------------------------------------------------------------------------------\n\n");
    // string
    //The quick brown fox jumps over the lazy dog
    char* test_str = "The quick brown fox jumps over the lazy dog";
    
    __uint8_t* hash2 = Whirpool_4str(test_str);
    printf("\n -Wow, Whirlpool hash for string: \"%s\"\n", test_str);
    state_x(hash2);

    as_str = ASCIIfied_hex(hash2);
    printf("\nASCIIfied hex:\n%s\n", as_str);

    printf("\n\n=== you can use: # rhash -W <filename> to check hash value ====\n");


    // ========= Below - MANY tests of intermediate functions ====== 

    /*
    // -------- Common variables for each test. also output info for Testing --------
    __uint64_t L_pad;                               // length after padding - inits by calling get_blocks()
    __uint8_t* blocks = get_blocks(file, &L_pad);   // getting blocks for Whirlpool

    printf("\n0-st block:\n");
    __uint8_t* i_block = get_block_i(0, blocks);
    state_x(i_block);
    

    __uint8_t* test_K_i = (__uint8_t*) calloc(64,1); 
    *(test_K_i) = 0x04;
    *(test_K_i+1) = 0x61;
    *(test_K_i+2) = 0x01;*/


    //-------------------- Test Round functions -----------------------
    
    /*
    //------- Test gamma_f() -------
    gamma_f(i_block);
    printf("\nblock after tweaked S-box\n");
    state_x(i_block);*/

    /*    
    //------- Test pi_f() -------
    pi_f(i_block);
    printf("\nblock after shifting columns\n");
    state_x(i_block);
    */

    /*
    //------- Test thetta_f() -------
    __uint8_t* test_M = (__uint8_t*) calloc(64,1); 
    *(test_M) = 0x01;
    *(test_M+1) = 0x01;
    *(test_M+2) = 0x01;
    *(test_M+7) = 0x02;


    printf("\n test_M: \n");
    state_x(test_M);

    thetta_f(test_M);
    printf("\n test_M(in hex) after right multiply by diffusion Matrix: \n");
    state_x(test_M);
    state_x(C_diffusion);*/
    
    /*    
    //------- Test sigma_f() and rho() -------

    sigma_f(i_block, test_K_i);
    printf("\nblock after XORing with test-key\n");
    state_x(i_block);

    printf("\ntest-key:\n");
    state_x(test_K_i);

    printf("\nTest rho_f() on a result block and test-key:\n");
    rho_f(i_block, test_K_i);
    state_x(i_block);*/

    // --- END
    fclose(file);
    return 0;
}