#include <stdint.h>


#ifndef UNTITLED_RC6_H
#define UNTITLED_RC6_H

//параметры алгоритма
#define r 16                //количество раундов
#define b 16                //размер секретного ключа в битах
#define u 4                 //размерность регистров А, B, C, D в байтах
#define c (32 + u - 1) / u  // размер массива преобразованных ключей L

#define w 8*u

#define R24 (2 * r + 4)
#define lgw 5               //lg(u*8)

#define P_w 0xB7E15163      // e - 2
#define Q_w 0x9E3779B9      // золотое сечение -1

//циклические сдвиги
#define rotl32(x, y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define rotr32(x, y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))

struct registers {
    uint32_t A, B, C, D;
};

uint32_t *key_prepare(unsigned char *K);

struct registers rc6_encrypt(uint32_t *S, struct registers regs);

struct registers rc6_decrypt(uint32_t *S, struct registers regs);


#endif //UNTITLED_RC6_H
