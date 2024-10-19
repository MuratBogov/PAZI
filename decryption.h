/**
 * @file decryption.h
 * @brief Заголовочный файл для функций расшифрования файлов.
 */

#ifndef DECRYPTION_H
#define DECRYPTION_H

/**
 * @brief Функция для расшифрования файла.
 * 
 * @param input_file Имя входного файла для расшифрования.
 * @param output_file Имя выходного файла для сохранения расшифрованных данных.
 * @param password Пароль для генерации ключа расшифрования.
 * @return int Возвращает 0 при успешном расшифровании, иначе -1.
 */
int decrypt_file(const char *input_file, const char *output_file, const char *password);

#endif
