#include <stdio.h>
#include <openssl/bn.h>

// Utility function to print BIGNUM values
void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

// Calculate public key: y = g^x mod p
BIGNUM* calculate_public_key(BIGNUM *g, BIGNUM *x, BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *y = BN_new();
    BN_mod_exp(y, g, x, p, ctx);
    return y;
}

// Calculate message key: K = y^x mod p
BIGNUM* calculate_message_key(BIGNUM *y, BIGNUM *x, BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *K = BN_new();
    BN_mod_exp(K, y, x, p, ctx);
    return K;
}

// El-Gamal decryption: M = C2 * (C1^x)^(-1) mod p
BIGNUM* decrypt_elgamal(BIGNUM *C1, BIGNUM *C2, BIGNUM *x, BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *K = BN_new();
    BIGNUM *K_inv = BN_new();
    BIGNUM *M = BN_new();

    // K = C1^x mod p
    BN_mod_exp(K, C1, x, p, ctx);

    // K_inv = K^(-1) mod p
    BN_mod_inverse(K_inv, K, p, ctx);

    // M = C2 * K_inv mod p
    BN_mod_mul(M, C2, K_inv, p, ctx);

    BN_free(K);
    BN_free(K_inv);
    return M;
}

// Solve El-Gamal problem 1: find ya, yb, K, C1, and C2 given p, g, xa, xb, M
void solve_eg1() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *xa = BN_new();
    BIGNUM *xb = BN_new();
    BIGNUM *M = BN_new();

    BN_dec2bn(&p, "773");
    BN_dec2bn(&g, "200");
    BN_dec2bn(&xa, "333");
    BN_dec2bn(&xb, "603");
    BN_dec2bn(&M, "321");

    BIGNUM *ya = calculate_public_key(g, xa, p, ctx);
    BIGNUM *yb = calculate_public_key(g, xb, p, ctx);

    // Calculate K = yb^xa mod p
    BIGNUM *K = calculate_message_key(yb, xa, p, ctx);

    // C1 = g^xa mod p
    BIGNUM *C1 = BN_new();
    BN_mod_exp(C1, g, xa, p, ctx);

    // C2 = M * K mod p
    BIGNUM *C2 = BN_new();
    BN_mod_mul(C2, M, K, p, ctx);

    printf("Problem 1:\n");
    printf("Alice's public key (ya) = %s\n", BN_bn2dec(ya));
    printf("Bob's public key (yb) = %s\n", BN_bn2dec(yb));
    printf("Message key (K) = %s\n", BN_bn2dec(K));
    printf("C1 = %s\n", BN_bn2dec(C1));
    printf("C2 = %s\n\n", BN_bn2dec(C2));

    BN_free(p);
    BN_free(g);
    BN_free(xa);
    BN_free(xb);
    BN_free(M);
    BN_free(ya);
    BN_free(yb);
    BN_free(K);
    BN_free(C1);
    BN_free(C2);
    BN_CTX_free(ctx);
}

// Solve El-Gamal problem 2: find K and M given p, g, xb, C1, C2
void solve_eg2() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *xb = BN_new();
    BIGNUM *C1 = BN_new();
    BIGNUM *C2 = BN_new();

    BN_dec2bn(&p, "6469");
    BN_dec2bn(&g, "5055");
    BN_dec2bn(&xb, "4127");
    BN_dec2bn(&C1, "3533");
    BN_dec2bn(&C2, "3719");

    // Calculate K = C1^xb mod p
    BIGNUM *K = BN_new();
    BN_mod_exp(K, C1, xb, p, ctx);

    // Decrypt the message
    BIGNUM *M = decrypt_elgamal(C1, C2, xb, p, ctx);

    printf("Problem 2:\n");
    printf("Message key (K) = %s\n", BN_bn2dec(K));
    printf("Decrypted message (M) = %s\n", BN_bn2dec(M));

    BN_free(p);
    BN_free(g);
    BN_free(xb);
    BN_free(C1);
    BN_free(C2);
    BN_free(K);
    BN_free(M);
    BN_CTX_free(ctx);
}

int main() {
    printf("\n=== El-Gamal Problems Solutions ===\n");
    solve_eg1();
    solve_eg2();
    return 0;
}
