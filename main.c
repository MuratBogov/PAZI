/**
 * @file main.c
 * @brief Основной файл программы для шифрования и расшифрования файлов с использованием OpenSSL.
 * 
 * Использует функции getopt для парсинга аргументов командной строки и вызывает функции
 * шифрования и расшифровки, реализованные в файлах encryption.c и decryption.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "encryption.h"
#include "decryption.h"

/**
 * @brief Выводит инструкцию по использованию программы.
 */
void print_usage() {
    printf("Usage:\n");
    printf("  ./enc_tool input_file output_file password  - Encrypt the file\n");
    printf("  ./enc_tool -d input_file output_file password  - Decrypt the file\n");
}

/**
 * @brief Главная функция программы.
 * 
 * @param argc Количество аргументов командной строки.
 * @param argv Массив аргументов командной строки.
 * @return int Код завершения программы (0 при успешном выполнении).
 */
int main(int argc, char *argv[]) {
    int decrypt_mode = 0;
    int opt;

    // Парсим аргументы командной строки
    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
            case 'd':
                decrypt_mode = 1;
                break;
            default:
                print_usage();
                return EXIT_FAILURE;
        }
    }

    // Проверяем, что достаточное количество аргументов передано
    if (argc - optind < 3) {
        print_usage();
        return EXIT_FAILURE;
    }

    char *input_file = argv[optind];
    char *output_file = argv[optind + 1];
    char *password = argv[optind + 2];

    if (decrypt_mode) {
        // Дешифрование
        if (decrypt_file(input_file, output_file, password) != 0) {
            fprintf(stderr, "Error decrypting file\n");
            return EXIT_FAILURE;
        }
    } else {
        // Шифрование
        if (encrypt_file(input_file, output_file, password) != 0) {
            fprintf(stderr, "Error encrypting file\n");
            return EXIT_FAILURE;
        }
    }

    printf("Operation completed successfully\n");
    return EXIT_SUCCESS;
}
