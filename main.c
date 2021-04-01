#include <stdio.h>
#include <stdint.h>
#include "rc6.h"

#define block_size 16 //32*4/8
#define block_count 4
#define msg_size block_size*block_count

//мапит регистры rc6 в текстовый блок
typedef union block {
    struct registers regs;
    char chars[block_size];
} block;

block xor(block* a, block* d){
    union block res = {0};
    for(int i = 0; i<block_size;i++){
        res.chars[i] = a->chars[i]^d->chars[i];
    }
    return res;
}

block iv = {0xAAFFBBCC, 0xAAFFBBCC, 0xAAFFBBCC, 0xAAFFBBCC};
unsigned char test_key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78};

int main() {
    block message[block_count] = {0};
    block e_msg[block_count] = {0};
    block d_msg[block_count] = {0};

    gets_s(message->chars, msg_size);
    printf("Message: %s\n", message->chars);

    uint32_t * p_keys = key_prepare(test_key);

    //шифруем вектор инициализации
    block e_iv = {0};
    e_iv.regs = rc6_encrypt(p_keys, iv.regs);
    e_msg[0] =  xor(&message[0],&e_iv);

    //cfb encrypt
    for (int i = 1; i < block_count; i ++) {
        e_msg[i].regs =  rc6_encrypt(p_keys,e_msg[i-1].regs);   //перешифровываем предыдущий шифрованный блок
        e_msg[i] = xor(&message[i], &e_msg[i]);                     //xor между открытым текстом и перешифрованным блоком
    }
    printf("Encrypted message: %s\n", e_msg->chars);

    //cfb decrypt
    d_msg[0] = xor(&e_msg[0],&e_iv);
    for (int i = 1; i < block_count; i ++) {
        d_msg[i].regs = rc6_encrypt(p_keys, d_msg[i].regs);
        d_msg[i] =  xor(&e_msg[i],&d_msg[i-1]);
    }
    printf("Decrypted message: %s\n", d_msg->chars);

    return 0;
}
