#include <stdio.h>
#include <openssl/bn.h>


// Function to print a BIGNUM in decimal format
void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}


int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p, *g, *xa, *xb, *ya, *yb, *kab, *kab_verify;

    printf("Diffie-Hellman Key Exchange Solutions\n");
    printf("=====================================\n\n");

    /* Problem 1: p = 773, g = 200, xa = 333, xb = 603, ya = ?, yb = ?, Kab = ? */
    printf("Problem 1: p = 773, g = 200, xa = 333, xb = 603\n");

    p = BN_new(); g = BN_new(); xa = BN_new(); xb = BN_new();
    ya = BN_new(); yb = BN_new(); kab = BN_new(); kab_verify = BN_new();

    BN_dec2bn(&p, "773");
    BN_dec2bn(&g, "200");
    BN_dec2bn(&xa, "333");
    BN_dec2bn(&xb, "603");

    // Calculate ya = g^xa mod p
    BN_mod_exp(ya, g, xa, p, ctx);
    printBN("ya =", ya);

    // Calculate yb = g^xb mod p
    BN_mod_exp(yb, g, xb, p, ctx);
    printBN("yb =", yb);

    // Calculate Kab = yb^xa mod p
    BN_mod_exp(kab, yb, xa, p, ctx);
    printBN("Kab =", kab);

    // Verify: Also calculate Kab as ya^xb mod p
    BN_mod_exp(kab_verify, ya, xb, p, ctx);
    printBN("Kab (verified) =", kab_verify);

    printf("\n");

    /* Problem 2: p = 1553, g = 307, xa = 1333, xb = 807, ya = ?, yb = ?, Kab = ? */
    printf("Problem 2: p = 1553, g = 307, xa = 1333, xb = 807\n");

    BN_dec2bn(&p, "1553");
    BN_dec2bn(&g, "307");
    BN_dec2bn(&xa, "1333");
    BN_dec2bn(&xb, "807");

    // Calculate ya = g^xa mod p
    BN_mod_exp(ya, g, xa, p, ctx);
    printBN("ya =", ya);

    // Calculate yb = g^xb mod p
    BN_mod_exp(yb, g, xb, p, ctx);
    printBN("yb =", yb);

    // Calculate Kab = yb^xa mod p
    BN_mod_exp(kab, yb, xa, p, ctx);
    printBN("Kab =", kab);

    // Verify: Also calculate Kab as ya^xb mod p
    BN_mod_exp(kab_verify, ya, xb, p, ctx);
    printBN("Kab (verified) =", kab_verify);

    // Clean up
    BN_free(p);
    BN_free(g);
    BN_free(xa);
    BN_free(xb);
    BN_free(ya);
    BN_free(yb);
    BN_free(kab);
    BN_free(kab_verify);
    BN_CTX_free(ctx);

    return 0;
}
