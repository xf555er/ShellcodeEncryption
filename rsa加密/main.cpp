#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>


using namespace std;

RSA* create_RSA(RSA* keypair, int pem_type, char* file_name) {
    FILE* fp = NULL;

    if (pem_type == 1) {
        fp = fopen(file_name, "w");
        PEM_write_RSAPublicKey(fp, keypair);
    }
    else if (pem_type == 2) {
        fp = fopen(file_name, "w");
        PEM_write_RSAPrivateKey(fp, keypair, NULL, NULL, 0, NULL, NULL);
    }

    fclose(fp);
    return keypair;
}

//bool EncryptionRSA(char* PublicKey, char* PriviateKey,unsigned char* Source, unsigned char* Encrypted) {
//    // Generate key pair
//    int bits = 2048;
//    RSA* keypair = RSA_new();
//    BIGNUM* bn = BN_new();
//
//    BN_set_word(bn, RSA_F4);
//    RSA_generate_key_ex(keypair, bits, bn, NULL);
//
//    // Save the keys into files
//    create_RSA(keypair, 1, PublicKey);  //…Ë÷√π´‘ø
//    create_RSA(keypair, 2, PriviateKey); //…Ë÷√ÀΩ‘ø
//
//    // Encrypt the shellcode
//    int encrypted_length = RSA_public_encrypt(strlen((char*)Source), Source, Encrypted, keypair, RSA_PKCS1_OAEP_PADDING);
//    if (encrypted_length == -1) {
//        cout << "Encryption Error: " << ERR_error_string(ERR_get_error(), NULL) << endl;
//        return false;
//    }
//    return true;
//}

//bool EncryptionRSA(char* PublicKey, char* PriviateKey, unsigned char* Source, unsigned char* Encrypted) {
//    
//}

bool DecryptionRSA(const char* privateKeyFile, unsigned char* encryptedData, int dataLength, unsigned char* decryptedData, int* decryptedLength) {
    FILE* fp = fopen(privateKeyFile, "rb");
    if (fp == NULL) {
        cerr << "Unable to open private key file" << endl;
        return false;
    }

    RSA* privateKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (privateKey == NULL) {
        cerr << "Unable to read private key from file" << endl;
        return false;
    }

    *decryptedLength = RSA_private_decrypt(dataLength, encryptedData, decryptedData, privateKey, RSA_PKCS1_OAEP_PADDING);
    RSA_free(privateKey);

    if (*decryptedLength == -1) {
        cerr << "Decryption error: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        return false;
    }

    return true;
}



int main() {
    //// Generate key pair
    //int bits = 2048;
    //RSA* keypair = RSA_new();
    //BIGNUM* bn = BN_new();

    //BN_set_word(bn, RSA_F4);
    //RSA_generate_key_ex(keypair, bits, bn, NULL);

    //// Save the keys into files
    //create_RSA(keypair, 1, (char*)"public.pem");  //…Ë÷√π´‘ø
    //create_RSA(keypair, 2, (char*)"private.pem"); //…Ë÷√ÀΩ‘ø

    //// Your shellcode here
    unsigned char Source[] = "HelloWorld";
   
    char PublicKey[] = "public.pem";
    char PrivateKey[] = "private.pem";

    /*unsigned char Encrypted[4096];
    EncryptionRSA(PublicKey, PrivateKey, Source, Encrypted);
    cout << Encrypted;*/

    // Encrypt the shellcode
    unsigned char encrypted[4096] = {};
    int encrypted_length = RSA_public_encrypt(shellcode.length(), (const unsigned char*)shellcode.c_str(), encrypted, keypair, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_length == -1) {
        cout << "Encryption Error: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        return -1;
    }
    cout << encrypted;

    // Decrypt the shellcode
    unsigned char decrypted[4096] = {};
    int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, keypair, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_length == -1) {
        cout << "Decryption Error: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        return -1;
    }

    cout << "Decrypted Shellcode: ";
    for (int i = 0; i < decrypted_length; i++) {
        printf("%02x ", decrypted[i]);
    }
    
    cout << "Decrypted Shellcode: " << decrypted << endl;
   
 

    // Free the memory
    RSA_free(keypair);
    BN_free(bn);

    return 0;
}