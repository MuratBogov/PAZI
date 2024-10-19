/**
 * @file decryption.c
 * @brief Реализация функций расшифрования файлов с использованием OpenSSL.
 */

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "decryption.h"

#define AES_BLOCK_SIZE 16
#define KEY_LENGTH 32
#define SALT_LENGTH 8

/**
 * @brief Расшифровывает файл с использованием AES-256-CBC.
 * 
 * Функция читает соль из зашифрованного файла, генерирует ключ и IV из пароля
 * с использованием PBKDF2. Дешифрованные данные записываются в выходной файл.
 * 
 * @param input_file Имя входного файла для расшифрования.
 * @param output_file Имя выходного файла для сохранения расшифрованных данных.
 * @param password Пароль для генерации ключа расшифрования.
 * @return int Возвращает 0 при успешном выполнении, иначе -1.
 */
int decrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");

    if (!in || !out) {
        perror("File error");
        return -1;
    }

    // Чтение соли из входного файла
    unsigned char salt[SALT_LENGTH];
    fread(salt, 1, SALT_LENGTH, in);

    // Генерация ключа и IV из пароля
    unsigned char key[KEY_LENGTH], iv[AES_BLOCK_SIZE];
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (unsigned char *)password, strlen(password), 1, key, iv)) {
        fprintf(stderr, "Error generating key and IV\n");
        return -1;
    }

    // Инициализация контекста для дешифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char in_buf[1032], out_buf[1024];
    int in_len, out_len;

    while ((in_len = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len);
        fwrite(out_buf, 1, out_len, out);
    }

    if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) <= 0) {
        fprintf(stderr, "Decryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    fwrite(out_buf, 1, out_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}
