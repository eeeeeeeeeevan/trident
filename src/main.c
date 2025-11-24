#include "trident.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
// #include <linux/random.h>
#include <fcntl.h>
#include <errno.h>
ssize_t getline(char **restrict lineptr, size_t *restrict n, FILE *restrict stream);
typedef unsigned char uchar;

static void usage (const char* program_name);
static void errshow (currstat status);
static void generate_key();

static inline
void read_file (const char* filename, uchar* buffer, size_t size)
{
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        exit(1);
    }
    if (fread(buffer, 1, size, f) != size) {
        fprintf(stderr, "fail %s\n", filename);
        exit(1);
    }
    fclose(f);
}
// unused because no need
// uncomment if needed one day
//  __attribute__((__deprecated__)) 
// static inline
// void write_file (const char* filename, const uchar* buffer, size_t size)
// {
//     FILE* f = fopen(filename, "wb");
//     if (!f) {
//         perror("fopen writefile"); return;
//       //  exit(1);
//     }
//     if (fwrite(buffer, 1, size, f) != size) {
//         fprintf(stderr, "fail %s\n", filename); return;
//         // exit(1);
//     }
//     fclose(f);
// }

static 
currstat trident_enc_file (const char* keyfile, const char* infile, const char* outfile, double cpubias, unsigned int memwork)
{
    uchar key[MKEYSIZE];
    uchar iv[MKEYSIZE];
    hashes_t hash_keys; 
    memset(&hash_keys, 0xAA, sizeof(hashes_t));

    read_file(keyfile, key, MKEYSIZE);

    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return ERRIO;
    if (fread(iv, 1, MKEYSIZE, f) != MKEYSIZE) {
        fclose(f);
        return ERRIO;
    }
    fclose(f);

    trident_state_curr state;
    currstat status = trident_init(&state, iv, key, &hash_keys, cpubias, memwork);
    if (status != SUCCESS) return status;

    FILE* fin = fopen(infile, "rb");
    FILE* fout = fopen(outfile, "wb");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return ERRIO;
    }

    fwrite(iv, 1, MKEYSIZE, fout);
    fwrite(&memwork, 1, 1, fout); 

    uchar inbuf[BLOCKSIZE];
    uchar outbuf[BLOCKSIZE];
    bigint block_id = 0;
    size_t n;

    while ((n = fread(inbuf, 1, BLOCKSIZE, fin)) > 0) {
        if (n < BLOCKSIZE) {
            memset(inbuf + n, 0, BLOCKSIZE - n);
        }
        trident_enc(&state, outbuf, inbuf, block_id++);
        fwrite(outbuf, 1, BLOCKSIZE, fout);
    }

    fclose(fin);
    fclose(fout);
    trident_cleanup(&state);
    return SUCCESS;
}

static 
currstat trident_dec_file (const char* keyfile, const char* infile, const char* outfile)
{
    uchar key[MKEYSIZE];
    uchar iv[MKEYSIZE];
    hashes_t hash_keys;
    memset(&hash_keys, 0xAA, sizeof(hashes_t));

    read_file(keyfile, key, MKEYSIZE);

    FILE* fin = fopen(infile, "rb");
    FILE* fout = fopen(outfile, "wb");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return ERRIO;
    }

    if (fread(iv, 1, MKEYSIZE, fin) != MKEYSIZE) {
        fclose(fin);
        fclose(fout);
        return ERRIO;
    }

    uchar memwork;
    if (fread(&memwork, 1, 1, fin) != 1) {  
        fclose(fin);
        fclose(fout);
        return ERRIO;
    }

    trident_state_curr state;
    currstat status = trident_init(&state, iv, key, &hash_keys, 1.0, memwork); 
    if (status != SUCCESS) {
        fclose(fin);
        fclose(fout);
        return status;
    }

    uchar inbuf[BLOCKSIZE];
    uchar outbuf[BLOCKSIZE];
    bigint block_id = 0;
    size_t n;

    while ((n = fread(inbuf, 1, BLOCKSIZE, fin)) == BLOCKSIZE) {
        trident_dec(&state, outbuf, inbuf, block_id++);
        fwrite(outbuf, 1, BLOCKSIZE, fout);
    }

    fclose(fin);
    fclose(fout);
    trident_cleanup(&state);
    return SUCCESS;
}

int main (int argc, char** argp)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc <= 1) {
        usage(argp[0]);
        return 0;
    }

    const char* modething = argp[1];
    if (!modething) return 1;
    int encmode;

    if (strcmp(modething, "enc") == 0 || strcmp(modething, "0") == 0) {
        encmode = 1;
    } else if (strcmp(modething, "dec") == 0 || strcmp(modething, "1") == 0) {
        encmode = 0;
    }  else if (strcmp(modething, "keygen") == 0) {
        encmode = 2;
        generate_key();
        return 0;
    } else {
        fprintf(stderr, "??\n");
        usage(argp[0]);
        return 1;
    }

    const char* keyfile, *infile, *outfile;
    double cpubias = 1.0; 
    uint memwork = 24;    

    if (encmode) {
        if (argc >= 5) {
            keyfile = argp[2];
            infile = argp[3];
            outfile = argp[4];
         
        } else {
            usage(argp[0]);
            return 1;
        }
    } else if (!encmode && argc == 5) {
        keyfile = argp[2];
        infile = argp[3];
        outfile = argp[4];
    } else {
        usage(argp[0]);
        return 1;
    }

    printf("trident - operating mode:  %s\n", encmode ? "encrypt" : "decrypt");

    if (encmode) {
        printf("using: %u (%.1f mb)\n", memwork, (1ULL<<memwork) / (1024.0*1024.0));
    }

    currstat status;
    if (encmode) {
        status = trident_enc_file(keyfile, infile, outfile, cpubias, memwork);
    } else {
        status = trident_dec_file(keyfile, infile, outfile);
    }

    if (status != SUCCESS) {
        fprintf(stderr, "\n");
        errshow(status);
        return 1;
    }

    puts("exiting");
    return 0;
}

static 
void usage (const char* program_name)
{
    puts("trident: basic spn block cipher");
    printf("  %s enc <keyfile> <input> <output>\n", 
           program_name);
    
    puts("decrypt:");
    printf("  %s dec <keyfile> <input> <output>\n", program_name);
    
    puts("generate an encryption key:");
    printf("  %s keygen\n", program_name);
}

static 
void errshow (currstat status)
{
    switch (status) {
        case ERRORALLOC:
            fprintf(stderr, "memalloc fail\n");
            break;
        case ERRINVPARAM:
            fprintf(stderr, "inv param provided\n");
            break;
        case ERRIO:
            fprintf(stderr, "i/o err\n");
            break;
        case ERRSCHECKF:
            fprintf(stderr, "cipher init sc failed\n");
            break;
        case INVFILEERR:
            fprintf(stderr, "bro wtf???\n");
            break;
        default:
            fprintf(stderr, "%d\n", status);
            break;
    }
}

static 
void generate_key()
{
    // char name[100]; 
    char* name = NULL;
    size_t n = 0;

    uchar buf[MKEYSIZE];

    printf("write enc key name: ");
    ssize_t resp = getline(&name, &n, stdin);
    if (resp < 0) {
        perror("wtf");
        free(name);
        return;
    }
    // scanf("%99s", name);
    name[strcspn(name, "\n")] = 0;
    if (name[0] == '\0') {
        perror("no name");
        return;
    }
    for (size_t i=0; name[i] != '\0'; i++) {
         if (!(isalnum((unsigned char)name[i]) || name[i] == '_' || name[i] == '-'))
        {
            perror("invalid name bro (alphanumeric/-/_)");
            return;
        }

    }
    const char* home = getenv("HOME");
    if (!home) {
        perror("no home"); return;
    }
    char dirpath[350];
    snprintf(dirpath, sizeof(dirpath), "%s/.trident", home);
    char filepath[400];
    snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, name);
    if (mkdir(dirpath, 0700) != 0 && errno != EEXIST) {
        perror("fail dir"); return;
    }
    // ssize_t ret = syscall(SYS_getrandom, buf, MKEYSIZE, 0);
    FILE* rf = fopen("/dev/urandom", "rb");
        if (!rf) {
            perror("urandom");
            return;
        }
        if (fread(buf, 1, MKEYSIZE, rf) != MKEYSIZE) {
            perror("fread urandom");
            fclose(rf);
            return;
        }
    fclose(rf);
    
    int fd = open(filepath, O_WRONLY | O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
        perror("aw fuck");
        memset(buf, 0, MKEYSIZE);
        return;
    }
    if (write(fd, buf, MKEYSIZE) != MKEYSIZE) {
        perror("write fail");
        close(fd);
        memset(buf, 0, MKEYSIZE);
        return;
    }

    close(fd);

    volatile unsigned char* p = buf;
    for (size_t i = 0; i < MKEYSIZE; i++) p[i] = 0;
    
    // FILE* f = fopen("/dev/urandom", "rb");
    // if (!f) {
    //     perror("fopen urandom");
    //     exit(1);
    // }
    // if (fread(buf, 1, MKEYSIZE, f) != MKEYSIZE) {
    //     fclose(f);
    //     exit(1);
    // }
    // fclose(f);
    
    // write_file(name, buf, MKEYSIZE);
    printf("\nwritten out as %s\n", filepath);
}
