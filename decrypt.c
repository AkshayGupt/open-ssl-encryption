#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE

// Run Command: gcc -I../include/ [filename].c -L . -lcrypto -lssl
// gcc -I../include/ encrypt.c -L . -lcrypto -lssl

int encrypt_len = 256;   
char* result; 

char* readFile(char* filename){
    FILE *fp;
    long lSize;
    char *buffer;

    fp = fopen ( filename , "rb" );
    if( !fp ) perror( filename ),exit(1);

    fseek( fp , 0L , SEEK_END);
    lSize = ftell( fp );
    rewind( fp );

    /* allocate memory for entire content */
    buffer = calloc( 1, lSize+1 );
    if( !buffer ) fclose(fp),fputs("memory alloc fails",stderr),exit(1);

    /* copy the file into the buffer */
    if( 1!=fread( buffer , lSize, 1 , fp) )
    fclose(fp),free(buffer),fputs("entire read fails",stderr),exit(1);


    fclose(fp);

    return buffer;
}


RSA* get_rsa_from_private_key(char * private_key){
    BIO* keybio = BIO_new_mem_buf(private_key, -1);
    if (keybio == NULL) {
        fprintf(stderr, "failed to create key BIO");
    }


    FILE *pub = fopen("private-key.pem", "rb");

    RSA* rsa = PEM_read_RSAPrivateKey(pub, NULL, NULL, NULL);
    // printf("rsa result %p\n", rsa);
    BIO_free(keybio);

    fclose(pub);
    return rsa;
}



char * getDecrypted(char *encrypt, RSA *keypair){

    char * decrypt = malloc(encrypt_len);
    char *err;
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        // goto free_stuff;
    }
    // printf("Decrypted message: %s\n", decrypt);

    #ifdef WRITE_TO_FILE
    // Write the encrypted message to a file
        FILE *out = fopen("DecryptedClientMetaData.json", "w");
        fwrite(decrypt, sizeof(*decrypt),  RSA_size(keypair), out);
        fclose(out);
        printf("Decrypted message written to file.\n");
        return decrypt;
    #endif
}

char* calculateHash(char* filename){
    FILE* file = popen("sha256sum main.txt", "r");

    char buffer[64];
    if(fscanf(file, "%s", buffer) == 1){
        pclose(file);
        result = buffer;
        return result;
    }

    return "0";
}

int main(void) {
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   msg[KEY_LENGTH/8];  // Message to encrypt
    char   *encrypt = NULL;    // Encrypted message
    char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages



    pri_key = readFile("private-key.pem");


    /**Debug starts here

        #ifdef PRINT_KEYS
            printf("\n%s\n%s\n", pri_key);
        #endif

    Debug ends here **/
    
    char *enc = readFile("EncryptedClientMetaData.json");
    RSA *rsa  = get_rsa_from_private_key(pri_key);
    char *dec = getDecrypted(enc, rsa);


    struct json_object *parsed_json;
    struct json_object *sha256hash;

    parsed_json = json_tokener_parse(dec);
    json_object_object_get_ex(parsed_json, "sha256hash", &sha256hash);

    // printf("sha256hash %s\n", json_object_get_string(sha256hash));

    const char *hash_given_by_the_driver = json_object_get_string(sha256hash);

    char *hash_calculated;


    /*
        TODO:
            1. Generate hash value of main file
            2. Convert it to string
            3. Check if both the hashes matches
            4. print the outcome
    */

    
    hash_calculated = calculateHash("main.txt");
    int i=0;
    int len=strlen(hash_given_by_the_driver);
    // printf("Length == %d", len);
    for(i =0;i<len;i++){
        char ch1 =hash_calculated[i];
        char ch2 =hash_given_by_the_driver[i];
        // printf("%c == %c:%d\n", ch1,ch2,(ch1 == ch2));
        if(ch1==ch2 == 0){
            printf("File is either tampered or not from a authentic source.\n");
            return 0;
        }
    }
    
    printf("File comes from a authentic source and has not been tampered with.\n");






    // if(strcmp(&hash_given_by_the_driver, &hash_calculated) == 0){
    //     //Equal hashes
    //     printf("File comes from a authentic source and has not been tampered with.");
    // }

    // printf("Calculated_hash is:%s\nGiven_hash is:%s\n", buffer, hash_given_by_the_driver);
//     int len = strlen(buffer);
//  printf("Matching...\n %d", len);

//     if (strcmp(hash_given_by_the_driver, buffer) !=0){
//         printf("File is either tampered or not from a authentic source.");
//     }
//     else
//     printf("File comes from a authentic source and has not been tampered with.");


    free_stuff:
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);

    return 0;
}
