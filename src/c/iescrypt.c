/*
 * This file is part of iescrypt
 * Copyright 2018 Guillaume LE VAILLANT
 * Distributed under the GNU GPL v3 or later.
 * See the file LICENSE for terms of use and distribution.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "monocypher.h"

#ifndef _WIN32
/* Win32 requires the non-standard O_BINARY flag to open binary files.
 * Let's define it to nothing on standard architectures. */
#define O_BINARY 0
#endif


/*
 * Parameters
 */

#define CIPHER_KEY_LENGTH 32
#define IV_LENGTH 24
#define DIGEST_LENGTH 64
#define MAC_KEY_LENGTH 32
#define MAC_LENGTH 16
#define SALT_LENGTH 16
#define DH_KEY_LENGTH 32
#define PARAMETER_LENGTH 32
#define SIGNATURE_KEY_LENGTH 32
#define SIGNATURE_LENGTH 64
#define BUFFER_LENGTH 4096
#define CHECK_IF_ERROR(var) do \
  { \
    if(var == -1) \
    { \
      fprintf(stderr, "Error: %s: ", __FUNCTION__); \
      perror(""); \
      exit(EXIT_FAILURE); \
    } \
  } \
  while(0);
#define CHECK_IF_MEMORY_ERROR(var) do \
  { \
    if(var == NULL) \
    { \
      fprintf(stderr, "Error: %s: memory allocation failed\n", __FUNCTION__); \
      exit(EXIT_FAILURE); \
    } \
  } \
  while(0);


/*
 * Utils
 */

#if defined(_WIN32)
#include <windows.h>

void disable_terminal_echo()
{
  int r;
  DWORD terminal_attributes;
  HANDLE terminal_handle = GetStdHandle(STD_INPUT_HANDLE);

  if((terminal_handle == INVALID_HANDLE_VALUE) || (terminal_handle == NULL))
  {
    fprintf(stderr, "Error: %s: could not get terminal handle\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  r = GetConsoleMode(terminal_handle, &terminal_attributes);
  if(r == 0)
  {
    fprintf(stderr, "Error: %s: could not get terminal attributes\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  r = SetConsoleMode(terminal_handle, terminal_attributes & (~ENABLE_ECHO_INPUT));
  if(r == 0)
  {
    fprintf(stderr, "Error: %s: could not set terminal attributes\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
}

void enable_terminal_echo()
{
  int r;
  DWORD terminal_attributes;
  HANDLE terminal_handle = GetStdHandle(STD_INPUT_HANDLE);

  if((terminal_handle == INVALID_HANDLE_VALUE) || (terminal_handle == NULL))
  {
    fprintf(stderr, "Error: %s: could not get terminal handle\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  r = GetConsoleMode(terminal_handle, &terminal_attributes);
  if(r == 0)
  {
    fprintf(stderr, "Error: %s: could not get terminal attributes\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  r = SetConsoleMode(terminal_handle, terminal_attributes | ENABLE_ECHO_INPUT);
  if(r == 0)
  {
    fprintf(stderr, "Error: %s: could not set terminal attributes\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
}
#else
#include <termios.h>

void disable_terminal_echo()
{
  int r;
  struct termios terminal_attributes;

  r = tcgetattr(STDIN_FILENO, &terminal_attributes);
  CHECK_IF_ERROR(r);
  terminal_attributes.c_lflag &= ~ECHO;
  r = tcsetattr(STDIN_FILENO, TCSAFLUSH, &terminal_attributes);
  CHECK_IF_ERROR(r);
}

void enable_terminal_echo()
{
  int r;
  struct termios terminal_attributes;

  r = tcgetattr(STDIN_FILENO, &terminal_attributes);
  CHECK_IF_ERROR(r);
  terminal_attributes.c_lflag |= ECHO;
  r = tcsetattr(STDIN_FILENO, TCSAFLUSH, &terminal_attributes);
  CHECK_IF_ERROR(r);
}
#endif

void print_hex(uint8_t *data, uint32_t data_length)
{
  unsigned int i;

  for(i = 0; i < data_length; i++)
  {
    printf("%02x", data[i]);
  }
}

void read_data(int input, uint8_t *data, uint32_t data_length)
{
  size_t n = 0;
  ssize_t t = 0;

  do
  {
    t = read(input, data + n, data_length - n);
    CHECK_IF_ERROR(t);
    if(t == 0)
    {
      fprintf(stderr, "Error: %s: input stream too short\n", __FUNCTION__);
      exit(EXIT_FAILURE);
    }
    n += t;
  }
  while(n < data_length);
}

void write_data(int output, uint8_t *data, uint32_t data_length)
{
  size_t n = data_length;
  ssize_t t = 0;

  do
  {
    t = write(output, data + data_length - n, n);
    CHECK_IF_ERROR(t);
    n -= t;
  }
  while(n > 0);
}

void read_file(uint8_t **data, uint32_t *data_length, char *filename, uint32_t expected_length)
{
  int r;
  struct stat info;
  int input = open(filename, O_RDONLY | O_BINARY);

  CHECK_IF_ERROR(input);
  r = fstat(input, &info);
  CHECK_IF_ERROR(r);
  *data_length = info.st_size;
  if((expected_length > 0) && (expected_length != *data_length))
  {
    fprintf(stderr, "Error: %s: the file \"%s\" is not %u bytes long\n", __FUNCTION__, filename, expected_length);
    exit(EXIT_FAILURE);
  }
  *data = (uint8_t *) malloc(*data_length);
  CHECK_IF_MEMORY_ERROR(*data);
  read_data(input, *data, *data_length);
  close(input);
}

void write_file(char *filename, uint8_t *data, uint32_t data_length)
{
  int output = open(filename, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  CHECK_IF_ERROR(output);
  write_data(output, data, data_length);
  close(output);
}

#if defined(__linux__) && defined(__GLIBC__) && (__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 25)
#include <sys/random.h>
void random_data(uint8_t *data, uint32_t data_length)
{
  size_t n = data_length;
  ssize_t t = 0;

  do
  {
    t = getrandom(data + data_length - n, n, 0);
    CHECK_IF_ERROR(t);
    n -= t;
  }
  while(n > 0);
}
#elif defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
void random_data(uint8_t *data, uint32_t data_length)
{
  HCRYPTPROV prov;

  if(!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
  {
    fprintf(stderr, "Error: %s: could not get random data\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  if(!CryptGenRandom(prov, (DWORD) data_length, data))
  {
    fprintf(stderr, "Error: %s: could not get random data\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  if(!CryptReleaseContext(prov, 0))
  {
    fprintf(stderr, "Error: %s: could not get random data\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
}
#else
void random_data(uint8_t *data, uint32_t data_length)
{
  int input = open("/dev/urandom", O_RDONLY | O_NOCTTY | O_CLOEXEC | O_BINARY);

  CHECK_IF_ERROR(input);
  read_data(input, data, data_length);
  close(input);
}
#endif

uint32_t end_of_line(uint8_t *data, uint32_t data_length)
{
  uint8_t *ptr_n = memchr(data, '\n', data_length);
  uint8_t *ptr_r = memchr(data, '\r', data_length);
  uint8_t *ptr = (ptr_n == NULL) ? ptr_r : (((ptr_r == NULL) || (ptr_r > ptr_n)) ? ptr_n : ptr_r);

  if(ptr == NULL)
  {
    return(data_length);
  }
  else
  {
    return(ptr - data);
  }
}

void read_passphrase(uint8_t **passphrase, uint32_t *passphrase_length, char *filename)
{
  uint8_t *data;
  uint32_t data_length;

  read_file(&data, &data_length, filename, 0);
  *passphrase_length = end_of_line(data, data_length);
  *passphrase = (uint8_t *) malloc(*passphrase_length);
  CHECK_IF_MEMORY_ERROR(*passphrase);
  memcpy(*passphrase, data, *passphrase_length);
  free(data);
}

void get_passphrase(uint8_t **passphrase, uint32_t *passphrase_length, int verify)
{
  char *t;
  char buffer[BUFFER_LENGTH];

  disable_terminal_echo();
  printf("Enter the passphrase: ");
  t = fgets(buffer, BUFFER_LENGTH, stdin);
  if(t == NULL)
  {
    fprintf(stderr, "Error: %s: could not read passphrase\n", __FUNCTION__);
    enable_terminal_echo();
    exit(EXIT_FAILURE);
  }
  printf("\n");
  *passphrase_length = end_of_line((uint8_t *) buffer, BUFFER_LENGTH);
  *passphrase = (uint8_t *) malloc(*passphrase_length);
  if(*passphrase == NULL)
  {
    fprintf(stderr, "Error: %s: memory allocation failed\n", __FUNCTION__);
    enable_terminal_echo();
    exit(EXIT_FAILURE);
  }
  memcpy(*passphrase, buffer, *passphrase_length);
  if(verify != 0)
  {
    printf("Enter the passphrase again: ");
    t = fgets(buffer, BUFFER_LENGTH, stdin);
    if(t == NULL)
    {
      fprintf(stderr, "Error: %s: could not read passphrase\n", __FUNCTION__);
      enable_terminal_echo();
      exit(EXIT_FAILURE);
    }
    printf("\n");
    if(memcmp(buffer, *passphrase, end_of_line((uint8_t *) buffer, BUFFER_LENGTH)) != 0)
    {
      fprintf(stderr, "Error: %s: passphrases don't match\n", __FUNCTION__);
      enable_terminal_echo();
      exit(EXIT_FAILURE);
    }
  }
  enable_terminal_echo();
}


/*
 * Integrated encryption scheme
 */

void derive_keys(uint8_t *cipher_key, uint8_t *iv, uint8_t *mac_key, uint8_t *shared_secret, uint32_t shared_secret_length, uint8_t *salt)
{
  const uint32_t data_length = CIPHER_KEY_LENGTH + IV_LENGTH + MAC_KEY_LENGTH;
  uint8_t data[data_length];
  const uint32_t nb_blocks = 4096;
  uint8_t *work_area = (uint8_t *) malloc(1024 * nb_blocks);

  CHECK_IF_MEMORY_ERROR(work_area);
  crypto_argon2i(data, data_length, work_area, 4096, 3, shared_secret, shared_secret_length, salt, SALT_LENGTH);
  memcpy(cipher_key, data, CIPHER_KEY_LENGTH);
  memcpy(iv, data + CIPHER_KEY_LENGTH, IV_LENGTH);
  memcpy(mac_key, data + CIPHER_KEY_LENGTH + IV_LENGTH, MAC_KEY_LENGTH);
  crypto_wipe(data, data_length);
  free(work_area);
}

void ies_encrypt_stream(uint8_t *mac, uint8_t *shared_secret, uint32_t shared_secret_length, uint8_t *salt, int input, int output)
{
  uint8_t cipher_key[CIPHER_KEY_LENGTH];
  uint8_t iv[IV_LENGTH];
  uint8_t mac_key[MAC_KEY_LENGTH];
  uint8_t plain_text[BUFFER_LENGTH];
  uint8_t cipher_text[BUFFER_LENGTH];
  ssize_t r = 0;
  crypto_chacha_ctx cipher_ctx;
  crypto_poly1305_ctx mac_ctx;

  derive_keys(cipher_key, iv, mac_key, shared_secret, shared_secret_length, salt);
  crypto_chacha20_x_init(&cipher_ctx, cipher_key, iv);
  crypto_poly1305_init(&mac_ctx, mac_key);
  do
  {
    r = read(input, plain_text, BUFFER_LENGTH);
    CHECK_IF_ERROR(r);
    if(r > 0)
    {
      crypto_chacha20_encrypt(&cipher_ctx, cipher_text, plain_text, r);
      crypto_poly1305_update(&mac_ctx, cipher_text, r);
      write_data(output, cipher_text, r);
    }
  }
  while(r > 0);
  crypto_poly1305_final(&mac_ctx, mac);
  crypto_wipe(cipher_key, CIPHER_KEY_LENGTH);
  crypto_wipe(iv, IV_LENGTH);
  crypto_wipe(mac_key, MAC_KEY_LENGTH);
  crypto_wipe(plain_text, BUFFER_LENGTH);
}

void ies_decrypt_stream(uint8_t *mac, uint8_t *shared_secret, uint32_t shared_secret_length, uint8_t *salt, int input, int output)
{
  uint8_t cipher_key[CIPHER_KEY_LENGTH];
  uint8_t iv[IV_LENGTH];
  uint8_t mac_key[MAC_KEY_LENGTH];
  uint8_t plain_text[BUFFER_LENGTH];
  uint8_t cipher_text[BUFFER_LENGTH];
  ssize_t r = 0;
  crypto_chacha_ctx cipher_ctx;
  crypto_poly1305_ctx mac_ctx;

  derive_keys(cipher_key, iv, mac_key, shared_secret, shared_secret_length, salt);
  crypto_chacha20_x_init(&cipher_ctx, cipher_key, iv);
  crypto_poly1305_init(&mac_ctx, mac_key);
  do
  {
    r = read(input, cipher_text, BUFFER_LENGTH);
    CHECK_IF_ERROR(r);
    if(r > 0)
    {
      crypto_poly1305_update(&mac_ctx, cipher_text, r);
      crypto_chacha20_encrypt(&cipher_ctx, plain_text, cipher_text, r);
      write_data(output, plain_text, r);
    }
  }
  while(r > 0);
  crypto_poly1305_final(&mac_ctx, mac);
  crypto_wipe(cipher_key, CIPHER_KEY_LENGTH);
  crypto_wipe(iv, IV_LENGTH);
  crypto_wipe(mac_key, MAC_KEY_LENGTH);
  crypto_wipe(cipher_text, BUFFER_LENGTH);
}


/*
 * Encryption, decryption, signature and verification functions
 */

void make_encryption_key_pair(char *filename)
{
  uint8_t private_key[DH_KEY_LENGTH];
  uint8_t public_key[DH_KEY_LENGTH];
  char *filename_pub = (char *) malloc(strlen(filename) + 5);

  CHECK_IF_MEMORY_ERROR(filename_pub);
  strcpy(filename_pub, filename);
  strcat(filename_pub, ".pub");
  random_data(private_key, DH_KEY_LENGTH);
  crypto_x25519_public_key(public_key, private_key);
  write_file(filename, private_key, DH_KEY_LENGTH);
  write_file(filename_pub, public_key, DH_KEY_LENGTH);
  crypto_wipe(private_key, DH_KEY_LENGTH);
  free(filename_pub);
}

void make_signing_key_pair(char *filename)
{
  uint8_t private_key[SIGNATURE_KEY_LENGTH];
  uint8_t public_key[SIGNATURE_KEY_LENGTH];
  char *filename_pub = (char *) malloc(strlen(filename) + 5);

  CHECK_IF_MEMORY_ERROR(filename_pub);
  strcpy(filename_pub, filename);
  strcat(filename_pub, ".pub");
  random_data(private_key, SIGNATURE_KEY_LENGTH);
  crypto_sign_public_key(public_key, private_key);
  write_file(filename, private_key, SIGNATURE_KEY_LENGTH);
  write_file(filename_pub, public_key, SIGNATURE_KEY_LENGTH);
  crypto_wipe(private_key, SIGNATURE_KEY_LENGTH);
  free(filename_pub);
}

void encrypt_file_with_key(char *input_file, char *output_file, char* public_key_file)
{
  uint8_t private_key[DH_KEY_LENGTH];
  uint8_t parameter[DH_KEY_LENGTH];
  uint8_t *public_key;
  uint32_t public_key_length;
  uint8_t shared_secret[DH_KEY_LENGTH];
  uint8_t salt[SALT_LENGTH];
  uint8_t mac[MAC_LENGTH];
  int r = 0;
  int input = open(input_file, O_RDONLY | O_BINARY);
  int output = open(output_file, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  CHECK_IF_ERROR(input);
  CHECK_IF_ERROR(output);
  read_file(&public_key, &public_key_length, public_key_file, DH_KEY_LENGTH);
  random_data(private_key, DH_KEY_LENGTH);
  crypto_x25519_public_key(parameter, private_key);
  random_data(salt, SALT_LENGTH);
  r = crypto_x25519(shared_secret, private_key, public_key);
  if(r == -1)
  {
    fprintf(stderr, "Error: %s: bad public key\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  write_data(output, salt, SALT_LENGTH);
  write_data(output, parameter, DH_KEY_LENGTH);
  r = lseek(output, SALT_LENGTH + DH_KEY_LENGTH + MAC_LENGTH, SEEK_SET);
  CHECK_IF_ERROR(r);
  ies_encrypt_stream(mac, shared_secret, DH_KEY_LENGTH, salt, input, output);
  r = lseek(output, SALT_LENGTH + DH_KEY_LENGTH, SEEK_SET);
  CHECK_IF_ERROR(r);
  write_data(output, mac, MAC_LENGTH);
  crypto_wipe(private_key, DH_KEY_LENGTH);
  crypto_wipe(shared_secret, DH_KEY_LENGTH);
  free(public_key);
  close(input);
  close(output);
}

void decrypt_file_with_key(char *input_file, char *output_file, char* private_key_file)
{
  uint8_t *private_key;
  uint32_t private_key_length;
  uint8_t parameter[DH_KEY_LENGTH];
  uint8_t shared_secret[DH_KEY_LENGTH];
  uint8_t salt[SALT_LENGTH];
  uint8_t mac[MAC_LENGTH];
  uint8_t computed_mac[MAC_LENGTH];
  int r = 0;
  int input = open(input_file, O_RDONLY | O_BINARY);
  int output = open(output_file, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  CHECK_IF_ERROR(input);
  CHECK_IF_ERROR(output);
  read_file(&private_key, &private_key_length, private_key_file, DH_KEY_LENGTH);
  read_data(input, salt, SALT_LENGTH);
  read_data(input, parameter, DH_KEY_LENGTH);
  read_data(input, mac, MAC_LENGTH);
  r = crypto_x25519(shared_secret, private_key, parameter);
  if(r == -1)
  {
    fprintf(stderr, "Error: %s: bad public key\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  ies_decrypt_stream(computed_mac, shared_secret, DH_KEY_LENGTH, salt, input, output);
  if(crypto_verify16(mac, computed_mac) == -1)
  {
    fprintf(stderr, "Error: %s: invalid message authentication code\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  crypto_wipe(private_key, DH_KEY_LENGTH);
  crypto_wipe(shared_secret, DH_KEY_LENGTH);
  free(private_key);
  close(input);
  close(output);
}

void encrypt_file_with_passphrase(char *input_file, char *output_file, char* passphrase_file)
{
  uint8_t *shared_secret;
  uint32_t shared_secret_length;
  uint8_t parameter[DH_KEY_LENGTH];
  uint8_t salt[SALT_LENGTH];
  uint8_t mac[MAC_LENGTH];
  int r = 0;
  int input = open(input_file, O_RDONLY | O_BINARY);
  int output = open(output_file, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  CHECK_IF_ERROR(input);
  CHECK_IF_ERROR(output);
  if(passphrase_file != NULL)
  {
    read_passphrase(&shared_secret, &shared_secret_length, passphrase_file);
  }
  else
  {
    get_passphrase(&shared_secret, &shared_secret_length, 1);
  }
  random_data(parameter, DH_KEY_LENGTH);
  random_data(salt, SALT_LENGTH);
  write_data(output, salt, SALT_LENGTH);
  write_data(output, parameter, DH_KEY_LENGTH);
  r = lseek(output, SALT_LENGTH + DH_KEY_LENGTH + MAC_LENGTH, SEEK_SET);
  CHECK_IF_ERROR(r);
  ies_encrypt_stream(mac, shared_secret, shared_secret_length, salt, input, output);
  r = lseek(output, SALT_LENGTH + DH_KEY_LENGTH, SEEK_SET);
  CHECK_IF_ERROR(r);
  write_data(output, mac, MAC_LENGTH);
  crypto_wipe(shared_secret, shared_secret_length);
  free(shared_secret);
  close(input);
  close(output);
}

void decrypt_file_with_passphrase(char *input_file, char *output_file, char* passphrase_file)
{
  uint8_t *shared_secret;
  uint32_t shared_secret_length;
  uint8_t parameter[DH_KEY_LENGTH];
  uint8_t salt[SALT_LENGTH];
  uint8_t mac[MAC_LENGTH];
  uint8_t computed_mac[MAC_LENGTH];
  int input = open(input_file, O_RDONLY | O_BINARY);
  int output = open(output_file, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  CHECK_IF_ERROR(input);
  CHECK_IF_ERROR(output);
  if(passphrase_file != NULL)
  {
    read_passphrase(&shared_secret, &shared_secret_length, passphrase_file);
  }
  else
  {
    get_passphrase(&shared_secret, &shared_secret_length, 0);
  }
  read_data(input, salt, SALT_LENGTH);
  read_data(input, parameter, DH_KEY_LENGTH);
  read_data(input, mac, MAC_LENGTH);
  ies_decrypt_stream(computed_mac, shared_secret, shared_secret_length, salt, input, output);
  if(crypto_verify16(mac, computed_mac) == -1)
  {
    fprintf(stderr, "Error: %s: invalid message authentication code\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  crypto_wipe(shared_secret, shared_secret_length);
  free(shared_secret);
  close(input);
  close(output);
}

void hash_file(uint8_t *hash, char *input_file)
{
  crypto_blake2b_ctx digest_ctx;
  uint8_t buffer[BUFFER_LENGTH];
  ssize_t r = 0;
  int input = open(input_file, O_RDONLY | O_BINARY);

  CHECK_IF_ERROR(input);
  crypto_blake2b_init(&digest_ctx);
  do
  {
    r = read(input, buffer, BUFFER_LENGTH);
    CHECK_IF_ERROR(r);
    crypto_blake2b_update(&digest_ctx, buffer, r);
  }
  while(r > 0);
  crypto_blake2b_final(&digest_ctx, hash);
  close(input);
}

void sign_file(char *input_file, char *signature_file, char *private_key_file)
{
  uint8_t *private_key;
  uint32_t private_key_length;
  uint8_t public_key[SIGNATURE_KEY_LENGTH];
  uint8_t hash[DIGEST_LENGTH];
  uint8_t signature[SIGNATURE_LENGTH];
  int output = open(signature_file, O_CREAT | O_WRONLY | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  CHECK_IF_ERROR(output);
  read_file(&private_key, &private_key_length, private_key_file, SIGNATURE_KEY_LENGTH);
  crypto_sign_public_key(public_key, private_key);
  hash_file(hash, input_file);
  crypto_sign(signature, private_key, public_key, hash, DIGEST_LENGTH);
  write_data(output, public_key, SIGNATURE_KEY_LENGTH);
  write_data(output, signature, SIGNATURE_LENGTH);
  crypto_wipe(private_key, SIGNATURE_KEY_LENGTH);
  free(private_key);
  close(output);
}

void verify_file_signature(char *input_file, char *signature_file, char *public_key_file)
{
  uint8_t *public_key = NULL;
  uint32_t public_key_length;
  uint8_t *signature_data;
  uint32_t signature_data_length;
  uint8_t signature_public_key[SIGNATURE_KEY_LENGTH];
  uint8_t signature[SIGNATURE_LENGTH];
  uint8_t hash[DIGEST_LENGTH];

  if(public_key_file != NULL)
  {
    read_file(&public_key, &public_key_length, public_key_file, SIGNATURE_KEY_LENGTH);
  }
  read_file(&signature_data, &signature_data_length, signature_file, SIGNATURE_KEY_LENGTH + SIGNATURE_LENGTH);
  memcpy(signature_public_key, signature_data, SIGNATURE_KEY_LENGTH);
  memcpy(signature, signature_data + SIGNATURE_KEY_LENGTH, SIGNATURE_LENGTH);
  hash_file(hash, input_file);
  if(((public_key != NULL) && (crypto_verify32(public_key, signature_public_key) == -1))
     || (crypto_check(signature, signature_public_key, hash, DIGEST_LENGTH) == -1))
  {
    fprintf(stderr, "Error: %s: bad signature\n", __FUNCTION__);
    exit(EXIT_FAILURE);
  }
  printf("Valid signature from ");
  print_hex(signature_public_key, SIGNATURE_KEY_LENGTH);
  printf("\n");
  free(signature_data);
  if(public_key != NULL)
  {
    free(public_key);
  }
}


/*
 * Commands for standalone program
 */

void print_usage()
{
  fprintf(stderr,
          "\niescrypt 1.0\n\n"
          "Usage: iescrypt-c <command> <arguments>\n\n"
          "Commands:\n\n"
          "  gen-enc <file>\n\n"
          "     Generate a key pair for encryption. The private key is written\n"
          "     to 'file' and the public key is written to 'file.pub'.\n\n\n"
          "  gen-sig <file>\n\n"
          "     Generate a key pair for signature. The private key is written\n"
          "     to 'file' and the public key is written to 'file.pub'.\n\n\n"
          "  enc <input file> <output file> <public key file>\n\n"
          "    Encrypt a file with a public key.\n\n\n"
          "  dec <input file> <output file> <private key file>\n\n"
          "    Decrypt a file that was encrypted with a public key using\n"
          "    the matching private key.\n\n\n"
          "  penc <input file> <output file> [passphrase file]\n\n"
          "    Encrypt a file using a passphrase.\n\n\n"
          "  pdec <input file> <output file> [passphrase file]\n\n"
          "    Decrypt a file using a passphrase.\n\n\n"
          "  sig <input file> <signature file> <private key file>\n\n"
          "    Sign a file with a private key.\n\n\n"
          "  ver <input-file> <signature-file> [public key file]\n\n"
          "    Verify a signature of a file.\n"
          "    If a public key file is specified, also verify that the signature\n"
          "    was made with the matching private key.\n");
}

int main(int argc, char **argv)
{
  if(argc >= 2)
  {
    if(strcasecmp(argv[1], "gen-enc") == 0)
    {
      if(argc == 3)
      {
        make_encryption_key_pair(argv[2]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "gen-sig") == 0)
    {
      if(argc == 3)
      {
        make_signing_key_pair(argv[2]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "enc") == 0)
    {
      if(argc == 5)
      {
        encrypt_file_with_key(argv[2], argv[3], argv[4]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "dec") == 0)
    {
      if(argc == 5)
      {
        decrypt_file_with_key(argv[2], argv[3], argv[4]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "penc") == 0)
    {
      if(argc == 4)
      {
        encrypt_file_with_passphrase(argv[2], argv[3], NULL);
        exit(EXIT_SUCCESS);
      }
      else if(argc == 5)
      {
        encrypt_file_with_passphrase(argv[2], argv[3], argv[4]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "pdec") == 0)
    {
      if(argc == 4)
      {
        decrypt_file_with_passphrase(argv[2], argv[3], NULL);
        exit(EXIT_SUCCESS);
      }
      else if(argc == 5)
      {
        decrypt_file_with_passphrase(argv[2], argv[3], argv[4]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "sig") == 0)
    {
      if(argc == 5)
      {
        sign_file(argv[2], argv[3], argv[4]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "ver") == 0)
    {
      if(argc == 4)
      {
        verify_file_signature(argv[2], argv[3], NULL);
        exit(EXIT_SUCCESS);
      }
      else if(argc == 5)
      {
        verify_file_signature(argv[2], argv[3], argv[4]);
        exit(EXIT_SUCCESS);
      }
    }
  }
  print_usage();
  fprintf(stderr, "\nError: invalid command\n");
  exit(EXIT_FAILURE);
}
