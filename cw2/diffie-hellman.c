#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a); // Forward declaration

// Calculate public key: y = g^x mod p
BIGNUM* calculate_public_key(BIGNUM *g, BIGNUM *x, BIGNUM *p) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *y = BN_new();

    BN_mod_exp(y, g, x, p, ctx);

    BN_CTX_free(ctx);
    return y;
}

// Calculate shared secret key: K = y^x mod p
BIGNUM* calculate_shared_key(BIGNUM *y, BIGNUM *x, BIGNUM *p) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *K = BN_new();

    BN_mod_exp(K, y, x, p, ctx);

    BN_CTX_free(ctx);
    return K;
}

void solve() {
    printf("\n=== Diffie-Hellman Problems Solutions ===\n");

    // Problem 1: p=773, g=200, xa=333, xb=603
    BIGNUM *p1 = BN_new();
    BIGNUM *g1 = BN_new();
    BIGNUM *xa1 = BN_new();
    BIGNUM *xb1 = BN_new();

    BN_dec2bn(&p1, "773");
    BN_dec2bn(&g1, "200");
    BN_dec2bn(&xa1, "333");
    BN_dec2bn(&xb1, "603");

    // Calculate Alice's public key: ya = g^xa mod p
    BIGNUM *ya1 = calculate_public_key(g1, xa1, p1);

    // Calculate Bob's public key: yb = g^xb mod p
    BIGNUM *yb1 = calculate_public_key(g1, xb1, p1);

    // Calculate shared secret key: Kab = yb^xa mod p
    BIGNUM *Kab1 = calculate_shared_key(yb1, xa1, p1);

    // Alternatively calculate: Kab = ya^xb mod p (should be the same)
    BIGNUM *Kab1_alt = calculate_shared_key(ya1, xb1, p1);

    printf("Problem 1:\n");
    printBN("Alice's public key (ya) =", ya1);
    printBN("Bob's public key (yb) =", yb1);
    printBN("Shared secret key (Kab) =", Kab1);
    printBN("Shared secret key (alternative calculation) =", Kab1_alt);

    // Problem 2: p=1553, g=307, xa=1333, xb=807
    BIGNUM *p2 = BN_new();
    BIGNUM *g2 = BN_new();
    BIGNUM *xa2 = BN_new();
    BIGNUM *xb2 = BN_new();

    BN_dec2bn(&p2, "1553");
    BN_dec2bn(&g2, "307");
    BN_dec2bn(&xa2, "1333");
    BN_dec2bn(&xb2, "807");

    // Calculate Alice's public key: ya = g^xa mod p
    BIGNUM *ya2 = calculate_public_key(g2, xa2, p2);

    // Calculate Bob's public key: yb = g^xb mod p
    BIGNUM *yb2 = calculate_public_key(g2, xb2, p2);

    // Calculate shared secret key: Kab = yb^xa mod p
    BIGNUM *Kab2 = calculate_shared_key(yb2, xa2, p2);

    // Alternatively calculate: Kab = ya^xb mod p (should be the same)
    BIGNUM *Kab2_alt = calculate_shared_key(ya2, xb2, p2);

    printf("\nProblem 2:\n");
    printBN("Alice's public key (ya) =", ya2);
    printBN("Bob's public key (yb) =", yb2);
    printBN("Shared secret key (Kab) =", Kab2);
    printBN("Shared secret key (alternative calculation) =", Kab2_alt);

    // Free all allocated memory
    BN_free(p1); BN_free(g1); BN_free(xa1); BN_free(xb1);
    BN_free(ya1); BN_free(yb1); BN_free(Kab1); BN_free(Kab1_alt);
    BN_free(p2); BN_free(g2); BN_free(xa2); BN_free(xb2);
    BN_free(ya2); BN_free(yb2); BN_free(Kab2); BN_free(Kab2_alt);
}

// Utility function to print BIGNUM values
void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    solve();
    return 0;
}
