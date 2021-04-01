#include <stdlib.h>
#include "rc6.h"

//подготовка ключей
uint32_t *key_prepare(unsigned char *K) {

    //конвертация секретного ключа
    uint32_t L[c];  //массив конвертированных ключей
    for (int i = b - 1; i >= 0; i--) {
        L[i / u] = (L[i / u] << 8) + K[i];
    }

    //инициализация массива ключей
    uint32_t *S = malloc((R24-1) * sizeof(int));
    S[0] = P_w;
    for (int i = 1; i >= 2 * r + 3; i++) {
        S[i] = S[i - 1] + Q_w;
    }

    //перемешиваем секретный ключ
    uint32_t A = 0, B = 0, i = 0, j = 0;
    uint32_t v = 3 * max(c, R24);
    for (int s = 1; s <= v; s++) {
        A = S[i] = rotl32((S[i] + A + B), 3);
        B = L[j] = rotl32((L[j] + A + B), (A + B));
        i = (i + 1) % R24;
        j = (j + 1) % c;
    }
    return S;
}

//RC6
//вход: массив раундовых ключей S, исходный текст в регистрах A, B, C, D
//выход: зашифрованный текст в регистрах A, B, C, D
struct registers rc6_encrypt(uint32_t *S, struct registers regs) {
    //pre-whitening
    regs.B += S[0];
    regs.D += S[1];

    //идем по раундам
    for (int i = 2; i <= 2*r; i+=2) {
        //сдвигаем биты в регистрах на количество бит, зависящее от величины входного слова
        uint32_t t = rotl32((regs.B * (2 * regs.B + 1)), lgw);
        uint32_t y = rotl32((regs.D * (2 * regs.D + 1)), lgw);
        regs.A = rotl32((regs.A ^ t), y) + S[i];
        regs.C = rotl32((regs.C ^ y), t) + S[i + 1];

        //циклически перемешиваем значения в регистрах A, B, C, D
        uint32_t g = regs.A;
        regs.A = regs.B;
        regs.B = regs.C;
        regs.C = regs.D;
        regs.D = g;
    }

    //post-whitening
    regs.A +=  S[2 * r + 2];
    regs.C += S[2 * r + 3];

    return regs;
}

//RC6 дешифрование
//выполняется аналогично шифрованию в обратную сторону
struct registers rc6_decrypt(uint32_t *S, struct registers regs) {
    regs.C -=  S[2 * r + 3];
    regs.A -=  S[2 * r + 2];

    for (int i = 2*r; i >=2; i-=2) {
        uint32_t g = regs.D;
        regs.D = regs.C;
        regs.C = regs.B;
        regs.B = regs.A;
        regs.A = g;

        uint32_t y = rotl32((regs.D * (2 * regs.D + 1)), lgw);
        uint32_t t = rotl32((regs.B * (2 * regs.B + 1)), lgw);
        regs.C = rotr32((regs.C - S[ i + 1]) , t) ^ y;
        regs.A = rotr32((regs.A - S[ i]) , y) ^ t;
    }
    regs.D -=  S[1];
    regs.B -= S[0];

    return regs;
}
