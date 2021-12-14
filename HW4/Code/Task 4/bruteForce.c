// Homework 4, Task 4 - Part 1
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//************ FUNCTIONS TO BE USED IN MAIN ************//

void rand_str(char *str)
{
    // generates random string of size 10 using alphanumerical chars
    for (int i = 0; i < 11; i++)
    {
        str[i] = rand() % 256 - 128;
    }
}

void generate_hash(char *hash, char *str, unsigned char *md_value)
{
    // based on sample code resource from Lab 4
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    int md_len;
    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname(hash);

    // error hadling
    if (!md)
    {
        printf("Unknown message digest %s\n", hash);
        exit(1);
    }

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, str, strlen(str));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);
}

int bruteForce_collision(char *hash)
{
    char msg_one[11], msg_two[11];
    unsigned char hash_one[EVP_MAX_MD_SIZE], hash_two[EVP_MAX_MD_SIZE];

    // the actual brute force algorithm
    int tries = 0;
    do
    {
        // create a random string & generate its hash
        rand_str(msg_one);
        generate_hash(hash, msg_one, hash_one);
        // create another random string & its hash
        rand_str(msg_two);
        generate_hash(hash, msg_two, hash_two);
        // increase the number of tries for each comparison
        tries++;

    } while (strncmp(hash_one, hash_two, 3) != 0); // compares first 3 bytes (3 bytes = 24 bits) of hash 1 and hash 2

    // print matching hash values
    printf("Matching Hash Values: %s", "\n");
    for (int i = 0; i < EVP_MAX_MD_SIZE; i++)
    {
        printf("%x", hash_one[i]);
    }
    printf("%s", "\n");
    for (int i = 0; i < EVP_MAX_MD_SIZE; i++)
    {
        printf("%x", hash_one[i]);
    }
    printf("\n");

    // print out the number of tries it took to crack the collision-free property
    printf("Collision-free Property cracked after %d tries!\n", tries);

    // return number of tries it took
    return tries;
}

//************ MAIN FUNCTION ************//
int main(int argc, char *argv[])
{
    // set the hash type to argument given by user
    char *hash;
    if (!argv[1])
    {
        // if no arg given, set default hash to md5
        hash = "md5";
    }
    else
    {
        // if arg given, use as hash type
        hash = argv[1];
    }

    // run algorithm five times and calculate average tries
    int tries = 0;

    for (int i = 0; i < 5; i++)
    {
        tries += bruteForce_collision(hash);
    }
    printf("Average tries to crack collision-free property: %d\n", tries / 5);
}