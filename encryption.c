/**
 * @file encryption.c
 * @brief Реализация функций шифрования файлов с использованием OpenSSL.
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "encryption.h"

#define AES_BLOCK_SIZE 16
#define KEY_LENGTH 32
#define SALT_LENGTH 8

/**
 * @brief Шифрует файл с использованием AES-256-CBC.
 * 
 * Функция генерирует соль и ключ из пароля с использованием PBKDF2.
 * Зашифрованные данные записываются в выходной файл.
 * 
 * @param input_file Имя входного файла для шифрования.
 * @param output_file Имя выходного файла для сохранения зашифрованных данных.
 * @param password Пароль для генерации ключа шифрования.
 * @return int Возвращает 0 при успешном выполнении, иначе -1.
 */
int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");

    if (!in || !out) {
        perror("File error");
        return -1;
    }

    // Генерация соли
    unsigned char salt[SALT_LENGTH];
    if (!RAND_bytes(salt, SALT_LENGTH)) {
        fprintf(stderr, "Error generating salt\n");
        return -1;
    }

    // Записываем соль в выходной файл
    fwrite(salt, 1, SALT_LENGTH, out);

    // Генерация ключа и IV из пароля
    unsigned char key[KEY_LENGTH], iv[AES_BLOCK_SIZE];
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (unsigned char *)password, strlen(password), 1, key, iv)) {
        fprintf(stderr, "Error generating key and IV\n");
        return -1;
    }

    // Инициализация контекста для шифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char in_buf[1024], out_buf[1032];
    int in_len, out_len;

    while ((in_len = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len);
        fwrite(out_buf, 1, out_len, out);
    }

    EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}
