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

// Calculate shared secret: K = y^x mod p
BIGNUM* calculate_shared_key(BIGNUM *y, BIGNUM *x, BIGNUM *p, BN_CTX *ctx) {
    BIGNUM *K = BN_new();
    BN_mod_exp(K, y, x, p, ctx);
    return K;
}

// Solve Diffie-Hellman problem 1: find ya, yb, and Kab given p, g, xa, xb
void solve_dh1() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *xa = BN_new();
    BIGNUM *xb = BN_new();

    BN_dec2bn(&p, "773");
    BN_dec2bn(&g, "200");
    BN_dec2bn(&xa, "333");
    BN_dec2bn(&xb, "603");

    BIGNUM *ya = calculate_public_key(g, xa, p, ctx);
    BIGNUM *yb = calculate_public_key(g, xb, p, ctx);
    BIGNUM *Kab = calculate_shared_key(yb, xa, p, ctx);

    printf("Problem 1:\n");
    printf("Alice's public key (ya) = %s\n", BN_bn2dec(ya));
    printf("Bob's public key (yb) = %s\n", BN_bn2dec(yb));
    printf("Shared secret key (Kab) = %s\n\n", BN_bn2dec(Kab));

    BN_free(p);
    BN_free(g);
    BN_free(xa);
    BN_free(xb);
    BN_free(ya);
    BN_free(yb);
    BN_free(Kab);
    BN_CTX_free(ctx);
}

// Solve Diffie-Hellman problem 2: find ya, yb, and Kab given p, g, xa, xb
void solve_dh2() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *xa = BN_new();
    BIGNUM *xb = BN_new();

    BN_dec2bn(&p, "1553");
    BN_dec2bn(&g, "307");
    BN_dec2bn(&xa, "1333");
    BN_dec2bn(&xb, "807");

    BIGNUM *ya = calculate_public_key(g, xa, p, ctx);
    BIGNUM *yb = calculate_public_key(g, xb, p, ctx);
    BIGNUM *Kab = calculate_shared_key(yb, xa, p, ctx);

    printf("Problem 2:\n");
    printf("Alice's public key (ya) = %s\n", BN_bn2dec(ya));
    printf("Bob's public key (yb) = %s\n", BN_bn2dec(yb));
    printf("Shared secret key (Kab) = %s\n\n", BN_bn2dec(Kab));

    BN_free(p);
    BN_free(g);
    BN_free(xa);
    BN_free(xb);
    BN_free(ya);
    BN_free(yb);
    BN_free(Kab);
    BN_CTX_free(ctx);
}

int main() {
    printf("\n=== Diffie-Hellman Solutions ===\n");
    solve_dh1();
    solve_dh2();
    return 0;
}
