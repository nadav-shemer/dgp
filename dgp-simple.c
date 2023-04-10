// A simple command-line password generator, using PBKDF2
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <openssl/evp.h>

#define SALT_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define DEFAULT_PBKDF2_ITERATIONS 260000
#define WORD_LIST_FILE "english.txt"
#define MAX_WORD_LENGTH 128
#define MAX_WORDS 2048

//void get_wordlist(char wordlist[][MAX_WORD_LENGTH]);
static char **get_wordlist(size_t *word_count) {
    FILE *file = fopen(WORD_LIST_FILE, "r");
    if (file == NULL) {
        perror("Error opening wordlist file");
        return NULL;
    }

    char **wordlist = malloc(MAX_WORDS * sizeof(char *));
    if (wordlist == NULL) {
        perror("Error allocating memory for wordlist");
        fclose(file);
        return NULL;
    }

    *word_count = 0;
    char line[MAX_WORD_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0'; // Remove the newline character

        wordlist[*word_count] = strdup(line);
        if (wordlist[*word_count] == NULL) {
            perror("Error allocating memory for word");
            break;
        }

        (*word_count)++;
        if (*word_count >= MAX_WORDS) {
            break;
        }
    }

    fclose(file);
    return wordlist;
}

void free_wordlist(char **wordlist, size_t word_count) {
    for (size_t i = 0; i < word_count; i++) {
        free(wordlist[i]);
    }
    free(wordlist);
}

//char *pbkdf2_hex(const char *data, const char *salt, int iterations, int keylen, const EVP_MD *hashfunc);
static void pbkdf2_hex(const char *data, const char *salt, int iterations, int keylen, const char *hashfunc, char *result) {
    unsigned char digest[keylen];
    const EVP_MD *digest_func = NULL;

    if (strcmp(hashfunc, "sha1") == 0) {
        digest_func = EVP_sha1();
    } else if (strcmp(hashfunc, "sha256") == 0) {
        digest_func = EVP_sha256();
    } else if (strcmp(hashfunc, "sha512") == 0) {
        digest_func = EVP_sha512();
    } else {
        printf("Unknown hash function: %s\n", hashfunc);
        return;
    }

    PKCS5_PBKDF2_HMAC(data, strlen(data), (unsigned char *)salt, strlen(salt), iterations, digest_func, keylen, digest);

    // Convert binary digest to hexadecimal representation
    for (int i = 0; i < keylen; i++) {
        sprintf(result + (i * 2), "%02x", digest[i]);
    }
}

void pbkdf2_bin(const uint8_t *data, size_t data_len, const uint8_t *salt, size_t salt_len, uint32_t iterations, uint32_t keylen, uint8_t *output) {
    PKCS5_PBKDF2_HMAC((const char *)data, data_len, salt, salt_len, iterations, EVP_sha1(), keylen, output);
}

const char *base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

//void get_base58(unsigned long long int_data, char *res);
static char *get_base58(const uint8_t *input, size_t input_size) {
    if (!input || input_size == 0) {
        printf("Invalid input.\n");
        return NULL;
    }

    // Calculate the maximum possible length of the resulting Base58 string
    size_t max_output_size = (input_size * 138 / 100) + 2; // Based on log(256) / log(58)

    char *base58_str = malloc(max_output_size);
    if (!base58_str) {
        printf("Memory allocation failed.\n");
        return NULL;
    }

    uint8_t *temp_input = malloc(input_size);
    if (!temp_input) {
        printf("Memory allocation failed.\n");
        free(base58_str);
        return NULL;
    }
    memcpy(temp_input, input, input_size);

    int index = 0;
    while (input_size > 0) {
        uint32_t carry = 0;
        int i;

        for (i = input_size - 1; i >= 0; i--) {
            uint32_t temp = ((uint32_t)temp_input[i]) + carry * 256;
            temp_input[i] = (uint8_t)(temp / 58);
            carry = temp % 58;
        }

        base58_str[index++] = base58_alphabet[carry];

        while (input_size > 0 && temp_input[0] == 0) {
            input_size--;
            memmove(temp_input, temp_input + 1, input_size);
        }
    }
    base58_str[index] = '\0';

    // Reverse the string since the encoding process produces the result in reverse order
    for (int i = 0, j = index - 1; i < j; i++, j--) {
        char temp = base58_str[i];
        base58_str[i] = base58_str[j];
        base58_str[j] = temp;
    }

    free(temp_input);
    return base58_str;
}


//int is_alnum(const char *string);
static bool is_alnum(const char *string) {
    bool has_lower = false;
    bool has_upper = false;
    bool has_digit = false;

    for (int i = 0; string[i] != '\0'; i++) {
        if (isdigit(string[i])) {
            has_digit = true;
        }
        if (islower(string[i])) {
            has_lower = true;
        }
        if (isupper(string[i])) {
            has_upper = true;
        }
    }

    return has_digit && has_lower && has_upper;
}

//void grab_alnum(unsigned long long int_data, int length, char *res);
static void grab_alnum(const uint8_t *data, size_t data_len, size_t length, char *res) {
    char *orig = get_base58(data, data_len);
    char *raw = orig;
    bool found_alnum = false;

    while (!found_alnum) {
        strncpy(res, raw, length);
        res[length] = '\0';

        if (is_alnum(res)) {
            found_alnum = true;
        } else {
            raw++;
        }
    }

    free(orig);
}

//void get_xkcd(unsigned long long int_data, char wordlist[][MAX_WORD_LENGTH], char *res);
static char **get_xkcd(const uint8_t *bin_data, size_t bin_data_len, char **wordlist, size_t word_count, size_t *picked_word_count) {
    const size_t bits_per_word = 11; // Since 2^11 = 2048, and the wordlist has 2048 words
    const size_t max_words = (bin_data_len * 8 + bits_per_word - 1) / bits_per_word;

    char **result = malloc(max_words * sizeof(char *));
    if (result == NULL) {
        perror("Error allocating memory for result");
        return NULL;
    }

    *picked_word_count = 0;
    size_t bit_pos = 0;
    while (bit_pos + bits_per_word <= bin_data_len * 8) {
        size_t index = 0;
        for (size_t i = 0; i < bits_per_word; i++) {
            size_t byte_pos = bit_pos / 8;
            size_t bit_in_byte = 7 - (bit_pos % 8);

            index |= ((bin_data[byte_pos] >> bit_in_byte) & 1) << (bits_per_word - 1 - i);
            bit_pos++;
        }

        result[*picked_word_count] = strdup(wordlist[index % word_count]);
        if (result[*picked_word_count] == NULL) {
            perror("Error allocating memory for picked word");
            break;
        }

        (*picked_word_count)++;
    }

    return result;
}

static void free_picked_words(char **picked_words, size_t picked_word_count) {
    for (size_t i = 0; i < picked_word_count; i++) {
        free(picked_words[i]);
    }
    free(picked_words);
}

static char *join_and_capitalize_words(char **words, size_t word_count) {
    size_t total_length = 0;
    for (size_t i = 0; i < word_count; ++i) {
        total_length += strlen(words[i]);
    }

    char *result = (char *)malloc(total_length + 1);
    if (result == NULL) {
        return NULL;
    }

    char *cursor = result;
    for (size_t i = 0; i < word_count; ++i) {
        size_t word_length = strlen(words[i]);
        strncpy(cursor, words[i], word_length);
        cursor[0] = toupper(cursor[0]);
        cursor += word_length;
    }
    result[total_length] = '\0';

    return result;
}

char *bin_to_hex(const unsigned char *bin_data, size_t bin_data_len) {
    static const char *hex_digits = "0123456789abcdef";
    char *hex_data = (char *)malloc(bin_data_len * 2 + 1); // Allocate memory for hex_data (1 byte in binary data = 2 hex digits)

    for (size_t i = 0; i < bin_data_len; i++) {
        hex_data[i * 2] = hex_digits[(bin_data[i] >> 4) & 0x0F]; // Get the upper 4 bits (nibble) and convert it to hex
        hex_data[i * 2 + 1] = hex_digits[bin_data[i] & 0x0F];    // Get the lower 4 bits (nibble) and convert it to hex
    }

    hex_data[bin_data_len * 2] = '\0'; // Null-terminate the hex_data string
    return hex_data;
}

//void generate(const char *seed, const char *name, const char *entry_type, const char *secret, char *res);
static char *generate(const char *seed, const char *name, const char *entry_type, const char *secret, char **wordlist, size_t word_count) {
    // Join seed and secret
    size_t seed_secret_len = strlen(seed) + strlen(secret) + 1;
    char *seed_secret = (char *)malloc(seed_secret_len);
    strcpy(seed_secret, seed);
    strcat(seed_secret, secret);
    uint8_t bin_data[40];
    pbkdf2_bin(seed_secret, seed_secret_len, name, strlen(name), 42000, 40, bin_data);
    char *result = NULL;

    if (strcmp(entry_type, "hex") == 0) {
        result = bin_to_hex(bin_data, 4);
    } else if (strcmp(entry_type, "hexlong") == 0) {
        result = bin_to_hex(bin_data, 8);
    } else if (strcmp(entry_type, "alnum") == 0) {
        char resbuf[9]; // 8 characters + null terminator
        grab_alnum(bin_data, sizeof(bin_data), 8, resbuf);
        result = strdup(resbuf);
    } else if (strcmp(entry_type, "alnumlong") == 0) {
        char resbuf[13]; // 12 characters + null terminator
        grab_alnum(bin_data, sizeof(bin_data), 12, resbuf);
        result = strdup(resbuf);
    } else if (strcmp(entry_type, "base58") == 0) {
        result = get_base58(bin_data, 8);
    } else if (strcmp(entry_type, "base58long") == 0) {
        result = get_base58(bin_data, 12);
    } else if (strcmp(entry_type, "xkcd") == 0) {
        size_t picked_word_count;
        char **picked_words = get_xkcd(bin_data, sizeof(bin_data), wordlist, word_count, &picked_word_count);
        result = join_and_capitalize_words(picked_words, picked_word_count);
        free_picked_words(picked_words, picked_word_count);
    } else if (strcmp(entry_type, "xkcdlong") == 0) {
        size_t picked_word_count;
        char **picked_words = get_xkcd(bin_data, sizeof(bin_data), wordlist, word_count, &picked_word_count);
        result = join_and_capitalize_words(picked_words, picked_word_count);
        free_picked_words(picked_words, picked_word_count);
    } else {
        result = strdup("unknown type");
    }
    return result;
}

//void test_vector_wrapper(const char *seed, const char *account, const char *name, const char *entry_type, char *res);
void test_vector_wrapper(const char *seed, const char *account, const char *name, const char *entry_type, char *output) {
    char **wordlist;
    size_t word_count;
    
    // Get the wordlist and its count
    wordlist = get_wordlist(&word_count);

    // Call the generate function with the provided parameters and wordlist
    char *result = generate(seed, name, entry_type, account, wordlist, word_count);

    // Free the memory allocated for the wordlist
    for (size_t i = 0; i < word_count; i++) {
        free(wordlist[i]);
    }
    free(wordlist);

    strcpy(output, result);
}

//unsigned long long gen_large_int(const char *seed, const char *name, const char *secret);
//void grab_xkcd(unsigned long long int_data, int count, char *res);

static void all_types(const char *seed, const char *account, const char *name) {
    const char *entry_types[] = {"hex", "hexlong", "alnum", "alnumlong", "base58", "base58long", "xkcd", "xkcdlong"};
    size_t num_entry_types = sizeof(entry_types) / sizeof(entry_types[0]);
    char **wordlist;
    size_t word_count;
    wordlist = get_wordlist(&word_count);

    printf("seed: %s, account: %s, name: %s\n", seed, account, name);
    for (size_t i = 0; i < num_entry_types; i++) {
        const char *entry_type = entry_types[i];
        char *result = generate(seed, name, entry_type, account, wordlist, word_count);
        printf("%s: %s\n", entry_type, result);
        free(result);
    }
    free_wordlist(wordlist, word_count);
}

//void some_types(const char *seed, const char *account, const char *name);
static void some_types(const char *seed, const char *account, const char *name) {
    const char *entry_types[] = {"hexlong", "alnum", "xkcdlong"};
    size_t num_entry_types = sizeof(entry_types) / sizeof(entry_types[0]);
    char **wordlist;
    size_t word_count;
    wordlist = get_wordlist(&word_count);

    printf("seed: %s, account: %s, name: %s\n", seed, account, name);
    for (size_t i = 0; i < num_entry_types; i++) {
        const char *entry_type = entry_types[i];
        char *result = generate(seed, name, entry_type, account, wordlist, word_count);
        printf("%s: %s\n", entry_type, result);
        free(result);
    }
    free_wordlist(wordlist, word_count);
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    printf("Usage: simple test-vectors\n");
    printf("OR simple <seed> <account> <name> <type>\n");
    return 0;
  }

  if (strcmp(argv[1], "test-vectors") == 0) {
    char res[128];
    test_vector_wrapper("a", "", "aa", "alnum", res);
    printf("a:aa:alnum: %s\n", res);
    test_vector_wrapper("aa", "", "a", "alnum", res);
    printf("aa:a:alnum: %s\n", res);
    test_vector_wrapper("a", "", "aa", "base58", res);
    printf("a:aa:base58: %s\n", res);
    test_vector_wrapper("a", "", "aa", "alnumlong", res);
    printf("a:aa:alnumlong: %s\n", res);
    const char *P = "passwordPASSWORDpassword";
    const char *S = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    all_types(P, "", S);
    all_types("pass", "word", "salt");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "salt");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "salt");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "default", "salt");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "default", "salt");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "default", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "default", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "default", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "default", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "test", "salt");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "test", "salt");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "test", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "test", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "test", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    some_types("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "test", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
  } else {
    char seed[256];
    char account[256];
    char name[256];
    char entry_type[256];
    strcpy(seed, argv[1]);
    strcpy(account, argv[2]);
    strcpy(name, argv[3]);
    strcpy(entry_type, argv[4]);
    char **wordlist;
    size_t word_count;
    
    // Get the wordlist and its count
    wordlist = get_wordlist(&word_count);
    char *result = generate(seed, name, entry_type, account, wordlist, word_count);
    printf("%s:%s:%s:%s\n", account, name, entry_type, result);
  }

  return 0;
}

#if 0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALTLEN 16
#define ITERATIONS 10000
#define KEYLEN 32

int main(int argc, char **argv)
{
    // Parse arguments - seed, account, name, type
    if (argc != 5) {
        printf("Usage: %s seed account name type\n", argv[0]);
        return 1;
    }
    char *seed = argv[1];
    char *account = argv[2];
    char *name = argv[3];
    char *type = argv[4];

}
#endif