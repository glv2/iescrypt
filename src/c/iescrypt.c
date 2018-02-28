/*
 * This file is part of iescrypt
 * Copyright 2018 Guillaume LE VAILLANT
 * Distributed under the GNU GPL v3 or later.
 * See the file LICENSE for terms of use and distribution.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "microtar.h"
#include "monocypher.h"


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


/*
 * Errors
 */

#define CHECK_IF_ERROR_TEMPLATE(condition) \
  do \
  { \
    if(condition) \
    { \
      fprintf(stderr, "Error: %s: %s\n", __func__, strerror(errno)); \
      exit(EXIT_FAILURE); \
    } \
  } \
  while(0)
#define CHECK_IF_ERROR(var) CHECK_IF_ERROR_TEMPLATE(var == -1)
#define CHECK_IF_MEMORY_ERROR(var) CHECK_IF_ERROR_TEMPLATE(var == NULL)
#define CHECK_IF_FILE_OPEN_ERROR(var) CHECK_IF_ERROR_TEMPLATE(var == NULL)
#define CHECK_IF_FILE_ERROR(var) CHECK_IF_ERROR_TEMPLATE(ferror(var))
#define CHECK_IF_TAR_ERROR(var) \
  do \
  { \
    if(var != MTAR_ESUCCESS) \
    { \
      fprintf(stderr, "Error: %s: %s\n", __func__, mtar_strerror(var)); \
      exit(EXIT_FAILURE); \
    } \
  } \
  while(0)


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
    fprintf(stderr, "Error: %s: could not get terminal handle\n", __func__);
    exit(EXIT_FAILURE);
  }
  r = GetConsoleMode(terminal_handle, &terminal_attributes);
  if(r == 0)
  {
    fprintf(stderr, "Error: %s: could not get terminal attributes\n", __func__);
    exit(EXIT_FAILURE);
  }
  r = SetConsoleMode(terminal_handle, terminal_attributes & (~ENABLE_ECHO_INPUT));
  if(r == 0)
  {
    fprintf(stderr, "Error: %s: could not set terminal attributes\n", __func__);
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
    fprintf(stderr, "Error: %s: could not get terminal handle\n", __func__);
    exit(EXIT_FAILURE);
  }
  r = GetConsoleMode(terminal_handle, &terminal_attributes);
  if(r == 0)
  {
    fprintf(stderr, "Error: %s: could not get terminal attributes\n", __func__);
    exit(EXIT_FAILURE);
  }
  r = SetConsoleMode(terminal_handle, terminal_attributes | ENABLE_ECHO_INPUT);
  if(r == 0)
  {
    fprintf(stderr, "Error: %s: could not set terminal attributes\n", __func__);
    exit(EXIT_FAILURE);
  }
}
#else
#include <termios.h>

void disable_terminal_echo()
{
  int r;
  struct termios terminal_attributes;

  r = tcgetattr(fileno(stdin), &terminal_attributes);
  CHECK_IF_ERROR(r);
  terminal_attributes.c_lflag &= ~ECHO;
  r = tcsetattr(fileno(stdin), TCSAFLUSH, &terminal_attributes);
  CHECK_IF_ERROR(r);
}

void enable_terminal_echo()
{
  int r;
  struct termios terminal_attributes;

  r = tcgetattr(fileno(stdin), &terminal_attributes);
  CHECK_IF_ERROR(r);
  terminal_attributes.c_lflag |= ECHO;
  r = tcsetattr(fileno(stdin), TCSAFLUSH, &terminal_attributes);
  CHECK_IF_ERROR(r);
}
#endif

void print_hex(uint8_t *data, size_t data_length)
{
  size_t i;

  for(i = 0; i < data_length; i++)
  {
    printf("%02x", data[i]);
  }
}

void read_data(FILE *input, uint8_t *data, size_t data_length)
{
  size_t n;

  while(data_length > 0)
  {
    n = fread(data, 1, data_length, input);
    CHECK_IF_FILE_ERROR(input);
    if(feof(input))
    {
      fprintf(stderr, "Error: %s: input stream too short\n", __func__);
      exit(EXIT_FAILURE);
    }
    data += n;
    data_length -= n;
  }
}

void write_data(FILE *output, uint8_t *data, size_t data_length)
{
  size_t n;

  while(data_length > 0)
  {
    n = fwrite(data, 1, data_length, output);
    CHECK_IF_FILE_ERROR(output);
    data += n;
    data_length -= n;
  }
}

void read_file(uint8_t **data, size_t *data_length, char *filename, size_t expected_length)
{
  int r;
  long int n;
  FILE *input = fopen(filename, "rb");

  CHECK_IF_FILE_OPEN_ERROR(input);
  r = fseek(input, 0, SEEK_END);
  CHECK_IF_ERROR(r);
  n = ftell(input);
  CHECK_IF_ERROR(n);
  *data_length = (size_t) n;
  if((expected_length > 0) && (expected_length != *data_length))
  {
    fprintf(stderr, "Error: %s: the file \"%s\" is not %lu bytes long\n", __func__, filename, expected_length);
    exit(EXIT_FAILURE);
  }
  *data = (uint8_t *) malloc(*data_length);
  CHECK_IF_MEMORY_ERROR(*data);
  r = fseek(input, 0, SEEK_SET);
  CHECK_IF_ERROR(r);
  read_data(input, *data, *data_length);
  fclose(input);
}

void write_file(char *filename, uint8_t *data, size_t data_length)
{
  FILE *output = fopen(filename, "wb");

  CHECK_IF_FILE_OPEN_ERROR(output);
  write_data(output, data, data_length);
  fclose(output);
}

#if defined(__linux__) && defined(__GLIBC__) && (__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 25)
#include <sys/random.h>

void random_data(uint8_t *data, unsigned int data_length)
{
  ssize_t n = 0;

  while(data_length > 0)
  {
    n = getrandom(data, data_length, 0);
    CHECK_IF_ERROR(n);
    data += n;
    data_length -= n;
  }
}
#elif defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>

void random_data(uint8_t *data, unsigned int data_length)
{
  HCRYPTPROV prov;

  if(!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
  {
    fprintf(stderr, "Error: %s: could not get random data\n", __func__);
    exit(EXIT_FAILURE);
  }
  if(!CryptGenRandom(prov, (DWORD) data_length, data))
  {
    fprintf(stderr, "Error: %s: could not get random data\n", __func__);
    exit(EXIT_FAILURE);
  }
  if(!CryptReleaseContext(prov, 0))
  {
    fprintf(stderr, "Error: %s: could not get random data\n", __func__);
    exit(EXIT_FAILURE);
  }
}
#else
void random_data(uint8_t *data, unsigned int data_length)
{
  FILE *input = fopen("/dev/urandom", "rb");

  CHECK_IF_FILE_OPEN_ERROR(input);
  read_data(input, data, data_length);
  fclose(input);
}
#endif

size_t end_of_line(uint8_t *data, size_t data_length)
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
  size_t data_length;

  read_file(&data, &data_length, filename, 0);
  *passphrase_length = (uint32_t) end_of_line(data, data_length);
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
    fprintf(stderr, "Error: %s: could not read passphrase\n", __func__);
    enable_terminal_echo();
    exit(EXIT_FAILURE);
  }
  printf("\n");
  *passphrase_length = end_of_line((uint8_t *) buffer, BUFFER_LENGTH);
  *passphrase = (uint8_t *) malloc(*passphrase_length);
  if(*passphrase == NULL)
  {
    fprintf(stderr, "Error: %s: memory allocation failed\n", __func__);
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
      fprintf(stderr, "Error: %s: could not read passphrase\n", __func__);
      enable_terminal_echo();
      exit(EXIT_FAILURE);
    }
    printf("\n");
    if(memcmp(buffer, *passphrase, end_of_line((uint8_t *) buffer, BUFFER_LENGTH)) != 0)
    {
      fprintf(stderr, "Error: %s: passphrases don't match\n", __func__);
      enable_terminal_echo();
      exit(EXIT_FAILURE);
    }
  }
  enable_terminal_echo();
}

char * get_temporary_filename(char *suffix)
{
  uint32_t id;
  char *filename = (char *) malloc(15 + strlen(suffix));

  CHECK_IF_MEMORY_ERROR(filename);
  random_data((uint8_t *) &id, 4);
  sprintf(filename, "tmp-%u%s", id, suffix);
  return(filename);
}

void make_tar_archive(char *archive_file, char *input_file, char* signature_file)
{
  int r;
  uint8_t data[BUFFER_LENGTH];
  size_t data_length;
  long int n;
  mtar_t archive;
  FILE *input = fopen(input_file, "rb");
  FILE *signature = fopen(signature_file, "rb");

  CHECK_IF_FILE_OPEN_ERROR(input);
  CHECK_IF_FILE_OPEN_ERROR(signature);
  r = mtar_open(&archive, archive_file, "w");
  CHECK_IF_TAR_ERROR(r);
  r = fseek(input, 0, SEEK_END);
  CHECK_IF_ERROR(r);
  n = ftell(input);
  CHECK_IF_ERROR(n);
  data_length = (size_t) n;
  r = fseek(input, 0, SEEK_SET);
  CHECK_IF_ERROR(r);
  r = mtar_write_file_header(&archive, input_file, data_length);
  CHECK_IF_TAR_ERROR(r);
  while(data_length > 0)
  {
    n = (data_length < BUFFER_LENGTH) ? data_length : BUFFER_LENGTH;
    read_data(input, data, n);
    r = mtar_write_data(&archive, data, n);
    CHECK_IF_TAR_ERROR(r);
    data_length -= n;
  }
  fclose(input);
  r = fseek(signature, 0, SEEK_END);
  CHECK_IF_ERROR(r);
  n = ftell(signature);
  CHECK_IF_ERROR(n);
  data_length = (size_t) n;
  r = fseek(signature, 0, SEEK_SET);
  CHECK_IF_ERROR(r);
  r = mtar_write_file_header(&archive, signature_file, data_length);
  CHECK_IF_TAR_ERROR(r);
  while(data_length > 0)
  {
    n = (data_length < BUFFER_LENGTH) ? data_length : BUFFER_LENGTH;
    read_data(signature, data, n);
    r = mtar_write_data(&archive, data, n);
    CHECK_IF_TAR_ERROR(r);
    data_length -= n;
  }
  fclose(signature);
  r = mtar_finalize(&archive);
  CHECK_IF_TAR_ERROR(r);
  r = mtar_close(&archive);
  CHECK_IF_TAR_ERROR(r);
}

void extract_tar_archive(char *archive_file, char *output_file, char *signature_file)
{
  int r;
  uint8_t data[BUFFER_LENGTH];
  size_t data_length;
  size_t n;
  mtar_t archive;
  mtar_header_t header_1;
  mtar_header_t header_2;
  mtar_header_t header_3;
  mtar_header_t *header_output;
  mtar_header_t *header_signature;
  FILE *output = fopen(output_file, "wb");
  FILE *signature = fopen(signature_file, "wb");

  CHECK_IF_FILE_OPEN_ERROR(output);
  CHECK_IF_FILE_OPEN_ERROR(signature);
  r = mtar_open(&archive, archive_file, "r");
  CHECK_IF_TAR_ERROR(r);
  r = mtar_read_header(&archive, &header_1);
  CHECK_IF_TAR_ERROR(r);
  r = mtar_next(&archive);
  CHECK_IF_TAR_ERROR(r);
  r = mtar_read_header(&archive, &header_2);
  CHECK_IF_TAR_ERROR(r);
  r = mtar_next(&archive);
  CHECK_IF_TAR_ERROR(r);
  r = mtar_read_header(&archive, &header_3);
  if(r != MTAR_ENULLRECORD)
  {
    fprintf(stderr, "Error: %s: unknown decrypted file format\n", __func__);
    exit(EXIT_FAILURE);
  }
  if(strlen(header_1.name) < strlen(header_2.name))
  {
    header_output = &header_1;
    header_signature = &header_2;
  }
  else
  {
    header_output = &header_2;
    header_signature = &header_1;
  }
  r = mtar_find(&archive, header_output->name, header_output);
  CHECK_IF_TAR_ERROR(r);
  data_length = header_output->size;
  while(data_length > 0)
  {
    n = (data_length < BUFFER_LENGTH) ? data_length : BUFFER_LENGTH;
    r = mtar_read_data(&archive, data, n);
    CHECK_IF_TAR_ERROR(r);
    write_data(output, data, n);
    data_length -= n;
  }
  fclose(output);
  r = mtar_find(&archive, header_signature->name, header_signature);
  CHECK_IF_TAR_ERROR(r);
  data_length = header_signature->size;
  while(data_length > 0)
  {
    n = (data_length < BUFFER_LENGTH) ? data_length : BUFFER_LENGTH;
    r = mtar_read_data(&archive, data, n);
    CHECK_IF_TAR_ERROR(r);
    write_data(signature, data, n);
    data_length -= n;
  }
  fclose(signature);
  r = mtar_close(&archive);
  CHECK_IF_TAR_ERROR(r);
}

void hash_file(uint8_t *hash, char *input_file)
{
  crypto_blake2b_ctx digest_ctx;
  uint8_t buffer[BUFFER_LENGTH];
  size_t n;
  FILE *input = fopen(input_file, "rb");

  CHECK_IF_FILE_OPEN_ERROR(input);
  crypto_blake2b_init(&digest_ctx);
  while(!feof(input))
  {
    n = fread(buffer, 1, BUFFER_LENGTH, input);
    CHECK_IF_FILE_ERROR(input);
    crypto_blake2b_update(&digest_ctx, buffer, n);
  }
  crypto_blake2b_final(&digest_ctx, hash);
  fclose(input);
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

void ies_encrypt_stream(uint8_t *mac, uint8_t *shared_secret, uint32_t shared_secret_length, uint8_t *salt, FILE *input, FILE *output)
{
  uint8_t cipher_key[CIPHER_KEY_LENGTH];
  uint8_t iv[IV_LENGTH];
  uint8_t mac_key[MAC_KEY_LENGTH];
  uint8_t plain_text[BUFFER_LENGTH];
  uint8_t cipher_text[BUFFER_LENGTH];
  size_t n;
  crypto_chacha_ctx cipher_ctx;
  crypto_poly1305_ctx mac_ctx;

  derive_keys(cipher_key, iv, mac_key, shared_secret, shared_secret_length, salt);
  crypto_chacha20_x_init(&cipher_ctx, cipher_key, iv);
  crypto_poly1305_init(&mac_ctx, mac_key);
  while(!feof(input))
  {
    n = fread(plain_text, 1, BUFFER_LENGTH, input);
    CHECK_IF_FILE_ERROR(input);
    if(n > 0)
    {
      crypto_chacha20_encrypt(&cipher_ctx, cipher_text, plain_text, n);
      crypto_poly1305_update(&mac_ctx, cipher_text, n);
      write_data(output, cipher_text, n);
    }
  }
  crypto_poly1305_final(&mac_ctx, mac);
  crypto_wipe(cipher_key, CIPHER_KEY_LENGTH);
  crypto_wipe(iv, IV_LENGTH);
  crypto_wipe(mac_key, MAC_KEY_LENGTH);
  crypto_wipe(plain_text, BUFFER_LENGTH);
}

void ies_decrypt_stream(uint8_t *mac, uint8_t *shared_secret, uint32_t shared_secret_length, uint8_t *salt, FILE *input, FILE *output)
{
  uint8_t cipher_key[CIPHER_KEY_LENGTH];
  uint8_t iv[IV_LENGTH];
  uint8_t mac_key[MAC_KEY_LENGTH];
  uint8_t plain_text[BUFFER_LENGTH];
  uint8_t cipher_text[BUFFER_LENGTH];
  size_t n;
  crypto_chacha_ctx cipher_ctx;
  crypto_poly1305_ctx mac_ctx;

  derive_keys(cipher_key, iv, mac_key, shared_secret, shared_secret_length, salt);
  crypto_chacha20_x_init(&cipher_ctx, cipher_key, iv);
  crypto_poly1305_init(&mac_ctx, mac_key);
  while(!feof(input))
  {
    n = fread(cipher_text, 1, BUFFER_LENGTH, input);
    CHECK_IF_FILE_ERROR(input);
    if(n > 0)
    {
      crypto_poly1305_update(&mac_ctx, cipher_text, n);
      crypto_chacha20_encrypt(&cipher_ctx, plain_text, cipher_text, n);
      write_data(output, plain_text, n);
    }
  }
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
  size_t public_key_length;
  uint8_t shared_secret[DH_KEY_LENGTH];
  uint8_t salt[SALT_LENGTH];
  uint8_t mac[MAC_LENGTH];
  int r;
  FILE *input = fopen(input_file, "rb");
  FILE *output = fopen(output_file, "wb");

  CHECK_IF_FILE_OPEN_ERROR(input);
  CHECK_IF_FILE_OPEN_ERROR(output);
  read_file(&public_key, &public_key_length, public_key_file, DH_KEY_LENGTH);
  random_data(private_key, DH_KEY_LENGTH);
  crypto_x25519_public_key(parameter, private_key);
  random_data(salt, SALT_LENGTH);
  r = crypto_x25519(shared_secret, private_key, public_key);
  if(r == -1)
  {
    fprintf(stderr, "Error: %s: bad public key\n", __func__);
    exit(EXIT_FAILURE);
  }
  write_data(output, salt, SALT_LENGTH);
  write_data(output, parameter, DH_KEY_LENGTH);
  r = fseek(output, SALT_LENGTH + DH_KEY_LENGTH + MAC_LENGTH, SEEK_SET);
  CHECK_IF_ERROR(r);
  ies_encrypt_stream(mac, shared_secret, DH_KEY_LENGTH, salt, input, output);
  r = fseek(output, SALT_LENGTH + DH_KEY_LENGTH, SEEK_SET);
  CHECK_IF_ERROR(r);
  write_data(output, mac, MAC_LENGTH);
  crypto_wipe(private_key, DH_KEY_LENGTH);
  crypto_wipe(shared_secret, DH_KEY_LENGTH);
  free(public_key);
  fclose(input);
  fclose(output);
}

void decrypt_file_with_key(char *input_file, char *output_file, char* private_key_file)
{
  uint8_t *private_key;
  size_t private_key_length;
  uint8_t parameter[DH_KEY_LENGTH];
  uint8_t shared_secret[DH_KEY_LENGTH];
  uint8_t salt[SALT_LENGTH];
  uint8_t mac[MAC_LENGTH];
  uint8_t computed_mac[MAC_LENGTH];
  int r;
  FILE *input = fopen(input_file, "rb");
  FILE *output = fopen(output_file, "wb");

  CHECK_IF_FILE_OPEN_ERROR(input);
  CHECK_IF_FILE_OPEN_ERROR(output);
  read_file(&private_key, &private_key_length, private_key_file, DH_KEY_LENGTH);
  read_data(input, salt, SALT_LENGTH);
  read_data(input, parameter, DH_KEY_LENGTH);
  read_data(input, mac, MAC_LENGTH);
  r = crypto_x25519(shared_secret, private_key, parameter);
  if(r == -1)
  {
    fprintf(stderr, "Error: %s: bad public key\n", __func__);
    exit(EXIT_FAILURE);
  }
  ies_decrypt_stream(computed_mac, shared_secret, DH_KEY_LENGTH, salt, input, output);
  if(crypto_verify16(mac, computed_mac) == -1)
  {
    fprintf(stderr, "Error: %s: invalid message authentication code\n", __func__);
    exit(EXIT_FAILURE);
  }
  crypto_wipe(private_key, DH_KEY_LENGTH);
  crypto_wipe(shared_secret, DH_KEY_LENGTH);
  free(private_key);
  fclose(input);
  fclose(output);
}

void encrypt_file_with_passphrase(char *input_file, char *output_file, char* passphrase_file)
{
  uint8_t *shared_secret;
  uint32_t shared_secret_length;
  uint8_t parameter[DH_KEY_LENGTH];
  uint8_t salt[SALT_LENGTH];
  uint8_t mac[MAC_LENGTH];
  int r;
  FILE *input = fopen(input_file, "rb");
  FILE *output = fopen(output_file, "wb");

  CHECK_IF_FILE_OPEN_ERROR(input);
  CHECK_IF_FILE_OPEN_ERROR(output);
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
  r = fseek(output, SALT_LENGTH + DH_KEY_LENGTH + MAC_LENGTH, SEEK_SET);
  CHECK_IF_ERROR(r);
  ies_encrypt_stream(mac, shared_secret, shared_secret_length, salt, input, output);
  r = fseek(output, SALT_LENGTH + DH_KEY_LENGTH, SEEK_SET);
  CHECK_IF_ERROR(r);
  write_data(output, mac, MAC_LENGTH);
  crypto_wipe(shared_secret, shared_secret_length);
  free(shared_secret);
  fclose(input);
  fclose(output);
}

void decrypt_file_with_passphrase(char *input_file, char *output_file, char* passphrase_file)
{
  uint8_t *shared_secret;
  uint32_t shared_secret_length;
  uint8_t parameter[DH_KEY_LENGTH];
  uint8_t salt[SALT_LENGTH];
  uint8_t mac[MAC_LENGTH];
  uint8_t computed_mac[MAC_LENGTH];
  FILE *input = fopen(input_file, "rb");
  FILE *output = fopen(output_file, "wb");

  CHECK_IF_FILE_OPEN_ERROR(input);
  CHECK_IF_FILE_OPEN_ERROR(output);
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
    fprintf(stderr, "Error: %s: invalid message authentication code\n", __func__);
    exit(EXIT_FAILURE);
  }
  crypto_wipe(shared_secret, shared_secret_length);
  free(shared_secret);
  fclose(input);
  fclose(output);
}

void sign_file(char *input_file, char *signature_file, char *private_key_file)
{
  uint8_t *private_key;
  size_t private_key_length;
  uint8_t public_key[SIGNATURE_KEY_LENGTH];
  uint8_t hash[DIGEST_LENGTH];
  uint8_t signature[SIGNATURE_LENGTH];
  FILE *output = fopen(signature_file, "wb");

  CHECK_IF_FILE_OPEN_ERROR(output);
  read_file(&private_key, &private_key_length, private_key_file, SIGNATURE_KEY_LENGTH);
  crypto_sign_public_key(public_key, private_key);
  hash_file(hash, input_file);
  crypto_sign(signature, private_key, public_key, hash, DIGEST_LENGTH);
  write_data(output, public_key, SIGNATURE_KEY_LENGTH);
  write_data(output, signature, SIGNATURE_LENGTH);
  crypto_wipe(private_key, SIGNATURE_KEY_LENGTH);
  free(private_key);
  fclose(output);
}

void verify_file_signature(char *input_file, char *signature_file, char *public_key_file)
{
  uint8_t *public_key = NULL;
  size_t public_key_length;
  uint8_t *signature_data;
  size_t signature_data_length;
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
    fprintf(stderr, "Error: %s: bad signature\n", __func__);
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

void sign_and_encrypt_file_with_key(char *input_file, char *output_file, char *signature_private_key_file, char* encryption_public_key_file)
{
  char *signature_file = (char *) malloc(strlen(input_file) + 5);
  char *archive_file = (char *) malloc(strlen(input_file) + 5);

  CHECK_IF_MEMORY_ERROR(signature_file);
  CHECK_IF_MEMORY_ERROR(archive_file);
  strcpy(signature_file, input_file);
  strcat(signature_file, ".sig");
  strcpy(archive_file, input_file);
  strcat(archive_file, ".tar");
  sign_file(input_file, signature_file, signature_private_key_file);
  make_tar_archive(archive_file, input_file, signature_file);
  encrypt_file_with_key(archive_file, output_file, encryption_public_key_file);
  remove(signature_file);
  remove(archive_file);
}

void decrypt_file_with_key_and_verify_signature(char *input_file, char *output_file, char *encryption_private_key_file, char *signature_public_key_file)
{
  char *signature_file = get_temporary_filename(".sig");
  char *archive_file = get_temporary_filename(".tar");

  decrypt_file_with_key(input_file, archive_file, encryption_private_key_file);
  extract_tar_archive(archive_file, output_file, signature_file);
  verify_file_signature(output_file, signature_file, signature_public_key_file);
  remove(signature_file);
  remove(archive_file);
  free(signature_file);
  free(archive_file);
}

void sign_and_encrypt_file_with_passphrase(char *input_file, char *output_file, char *signature_private_key_file, char* passphrase_file)
{
  char *signature_file = (char *) malloc(strlen(input_file) + 5);
  char *archive_file = (char *) malloc(strlen(input_file) + 5);

  CHECK_IF_MEMORY_ERROR(signature_file);
  CHECK_IF_MEMORY_ERROR(archive_file);
  strcpy(signature_file, input_file);
  strcat(signature_file, ".sig");
  strcpy(archive_file, input_file);
  strcat(archive_file, ".tar");
  sign_file(input_file, signature_file, signature_private_key_file);
  make_tar_archive(archive_file, input_file, signature_file);
  encrypt_file_with_passphrase(archive_file, output_file, passphrase_file);
  remove(signature_file);
  remove(archive_file);
}

void decrypt_file_with_passphrase_and_verify_signature(char *input_file, char *output_file, char *passphrase_file, char *signature_public_key_file)
{
  char *signature_file = get_temporary_filename(".sig");
  char *archive_file = get_temporary_filename(".tar");

  decrypt_file_with_passphrase(input_file, archive_file, passphrase_file);
  extract_tar_archive(archive_file, output_file, signature_file);
  verify_file_signature(output_file, signature_file, signature_public_key_file);
  remove(signature_file);
  remove(archive_file);
  free(signature_file);
  free(archive_file);
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
          "    was made with the matching private key.\n\n\n"
          "  sig-enc <input file> <output file> <signature private key file>\n"
          "          <encryption public key file>\n\n"
          "    Sign a file with a private key and encrypt the file and the signature\n"
          "    with a public key.\n\n\n"
          "  dec-ver <input file> <output file> <encryption private key file>\n"
          "          [signature public key file]\n\n"
          "    Decrypt a file with a private key and verify that it has a valid\n"
          "    signature. If a signature public key is specified, also verify that\n"
          "    the signature was made with the matching private key.\n\n\n"
          "  sig-penc <input file> <output file> <signature private key file>\n"
          "           [passphrase file]\n\n"
          "    Sign a file with a private key and encrypt the file and the signature\n"
          "    with a passphrase.\n\n\n"
          "  pdec-ver <input file> <output file>\n"
          "           [passphrase file [signature public key file]]\n\n"
          "    Decrypt a file with a passphrase and verify that it has a valid\n"
          "    signature. If a signature public key is specified, also verify that\n"
          "    the signature was made with the matching private key.\n\n");
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
    else if(strcasecmp(argv[1], "sig-enc") == 0)
    {
      if(argc == 6)
      {
        sign_and_encrypt_file_with_key(argv[2], argv[3], argv[4], argv[5]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "dec-ver") == 0)
    {
      if(argc == 5)
      {
        decrypt_file_with_key_and_verify_signature(argv[2], argv[3], argv[4], NULL);
        exit(EXIT_SUCCESS);
      }
      else if(argc == 6)
      {
        decrypt_file_with_key_and_verify_signature(argv[2], argv[3], argv[4], argv[5]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "sig-penc") == 0)
    {
      if(argc == 5)
      {
        sign_and_encrypt_file_with_passphrase(argv[2], argv[3], argv[4], NULL);
        exit(EXIT_SUCCESS);
      }
      else if(argc == 6)
      {
        sign_and_encrypt_file_with_passphrase(argv[2], argv[3], argv[4], argv[5]);
        exit(EXIT_SUCCESS);
      }
    }
    else if(strcasecmp(argv[1], "pdec-ver") == 0)
    {
      if(argc == 4)
      {
        decrypt_file_with_passphrase_and_verify_signature(argv[2], argv[3], NULL, NULL);
        exit(EXIT_SUCCESS);
      }
      else if(argc == 5)
      {
        decrypt_file_with_passphrase_and_verify_signature(argv[2], argv[3], argv[4], NULL);
        exit(EXIT_SUCCESS);
      }
      else if(argc == 6)
      {
        decrypt_file_with_passphrase_and_verify_signature(argv[2], argv[3], argv[4], argv[5]);
        exit(EXIT_SUCCESS);
      }
    }
  }
  print_usage();
  fprintf(stderr, "Error: invalid command\n");
  exit(EXIT_FAILURE);
}
