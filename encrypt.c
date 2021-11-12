#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE

// Run Command: gcc -I../include/ [filename].c -L . -lcrypto -lssl
// gcc -I../include/ encrypt.c -L . -lcrypto -lssl

int encrypt_len;

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

    /* do your work here, buffer is a string contains the whole text */

    fclose(fp);

    return buffer;
    // free(buffer);
}


RSA* get_rsa(char * public_key){
    BIO* keybio = BIO_new_mem_buf(public_key, -1);
    if (keybio == NULL) {
        fprintf(stderr, "failed to create key BIO");
    }


    FILE *pub = fopen("public-key.pem", "rb");



    RSA* rsa = PEM_read_RSAPublicKey(pub, NULL, NULL, NULL);
    BIO_free(keybio);

    fclose(pub);
    return rsa;
}


char * getEncrypted(char *msg, RSA *keypair){
   char * encrypt = malloc(RSA_size(keypair));
  
    char *err = malloc(130);
    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
    }

    printf("LENGTH: %d", encrypt_len);

    #ifdef WRITE_TO_FILE
    // Write the encrypted message to a file
    FILE *out = fopen("EncryptedClientMetaData.json", "w");
    fwrite(encrypt, sizeof(*encrypt),  RSA_size(keypair), out);
    fclose(out);
    printf("Encrypted message written to file.\n");
    return encrypt;
    #endif
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


    pub_key = readFile("public-key.pem");
    // pri_key = readFile("private-key.pem");

      RSA *rsa = get_rsa(pub_key);

    /** Debug starts here
    #ifdef PRINT_KEYS
        printf("\n%s\n%s\n", pri_key, pub_key);
    #endif
    printf("rsa result %p\n", rsa);
    Debug ends here**/


    char *message = readFile("ClientMetaData.json");

    //Encrypt the message and write to a file called "out.bin":
    getEncrypted(message, rsa);
   
    //Read encrypted file
    char *enc = readFile("out.bin");
  
    free_stuff:
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);

    return 0;
}
