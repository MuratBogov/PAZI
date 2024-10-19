/**
 * @file encryption.h
 * @brief Заголовочный файл для функций шифрования файлов.
 */

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

/**
 * @brief Функция для шифрования файла.
 * 
 * @param input_file Имя входного файла для шифрования.
 * @param output_file Имя выходного файла для сохранения зашифрованных данных.
 * @param password Пароль для генерации ключа шифрования.
 * @return int Возвращает 0 при успешном шифровании, иначе -1.
 */
int encrypt_file(const char *input_file, const char *output_file, const char *password);

#endif
