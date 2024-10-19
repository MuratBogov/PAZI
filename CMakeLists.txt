cmake_minimum_required(VERSION 3.10)
project(enc_tool)

# Устанавливаем стандарт C
set(CMAKE_C_STANDARD 11)

# Добавляем директорию OpenSSL
find_package(OpenSSL REQUIRED)

# Добавляем исполняемый файл и его зависимости
add_executable(enc_tool main.c encryption.c decryption.c)

# Линкуем OpenSSL
target_link_libraries(enc_tool OpenSSL::SSL OpenSSL::Crypto)
