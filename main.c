#include <stdio.h>
#include <openssl/bn.h>


// Function to print a BIGNUM in decimal format
void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}


// Function to compute private key d given p, q, and e
BIGNUM *compute_d(BIGNUM *p, BIGNUM *q, BIGNUM *e, BN_CTX *ctx) {
    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BIGNUM *d = BN_new();

    // Calculate phi = (p-1)*(q-1)
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(phi, p_minus_1, q_minus_1, ctx);

    // Calculate d = e^(-1) mod phi
    BN_mod_inverse(d, e, phi, ctx);

    BN_free(phi);
    BN_free(p_minus_1);
    BN_free(q_minus_1);

    return d;
}


// Function to encrypt a message M with public key (e,n)
BIGNUM *encrypt(BIGNUM *M, BIGNUM *e, BIGNUM *n, BN_CTX *ctx) {
    BIGNUM *C = BN_new();

    // C = M^e mod n
    BN_mod_exp(C, M, e, n, ctx);

    return C;
}


// Function to decrypt a ciphertext C with private key (d,n)
BIGNUM *decrypt(BIGNUM *C, BIGNUM *d, BIGNUM *n, BN_CTX *ctx) {
    BIGNUM *M = BN_new();

    // M = C^d mod n
    BN_mod_exp(M, C, d, n, ctx);

    return M;
}


// Function to verify a signature S using public key (e,n)
int verify_signature(BIGNUM *M, BIGNUM *S, BIGNUM *e, BIGNUM *n, BN_CTX *ctx) {
    BIGNUM *calculated_M = BN_new();
    int result;

    // M' = S^e mod n
    BN_mod_exp(calculated_M, S, e, n, ctx);

    // Compare M' with M
    result = (BN_cmp(calculated_M, M) == 0);

    BN_free(calculated_M);
    return result;
}


int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p, *q, *n, *e, *d, *M, *C, *S;

    printf("RSA Problem Solutions\n");
    printf("=====================\n\n");

    /* Problem 1: n = 6887, e = 143, M = 1234, d = ?, C = ? */
    printf("Problem 1: n = 6887, e = 143, M = 1234, d = ?, C = ?\n");
    n = BN_new(); e = BN_new(); M = BN_new();
    BN_dec2bn(&n, "6887");
    BN_dec2bn(&e, "143");
    BN_dec2bn(&M, "1234");

    // For this problem, we don't have p and q directly.
    // We would need to factor n to find p and q, which is difficult for large n.
    // However, for this small n, we can find the factors.
    // n = 6887 = 71 * 97
    p = BN_new(); q = BN_new();
    BN_dec2bn(&p, "71");
    BN_dec2bn(&q, "97");

    // Calculate d
    d = compute_d(p, q, e, ctx);
    printBN("d =", d);

    // Calculate C = M^e mod n
    C = encrypt(M, e, n, ctx);
    printBN("C =", C);

    printf("\n");

    /* Problem 2: n = 69353, e = ?, M = 12345, d = 29401, C = ? */
    printf("Problem 2: n = 69353, e = ?, M = 12345, d = 29401, C = ?\n");
    BN_free(n); BN_free(e); BN_free(M); BN_free(d); BN_free(C);
    n = BN_new(); M = BN_new(); d = BN_new();
    BN_dec2bn(&n, "69353");
    BN_dec2bn(&M, "12345");
    BN_dec2bn(&d, "29401");

    // Factor n to find p and q
    // n = 69353 = 251 * 277
    BN_free(p); BN_free(q);
    p = BN_new(); q = BN_new();
    BN_dec2bn(&p, "251");
    BN_dec2bn(&q, "277");

    // Calculate phi = (p-1)*(q-1)
    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(phi, p_minus_1, q_minus_1, ctx);

    // Find e such that e*d = 1 mod phi
    e = BN_new();
    BN_mod_inverse(e, d, phi, ctx);
    printBN("e =", e);

    // Calculate C = M^e mod n
    C = encrypt(M, e, n, ctx);
    printBN("C =", C);

    printf("\n");

    /* Problem 3: p = 37, q = 67, e = 169, M = ?, d = ?, C = 1744 */
    printf("Problem 3: p = 37, q = 67, e = 169, M = ?, d = ?, C = 1744\n");
    BN_free(p); BN_free(q); BN_free(e); BN_free(d); BN_free(M); BN_free(C);
    p = BN_new(); q = BN_new(); e = BN_new(); C = BN_new();
    BN_dec2bn(&p, "37");
    BN_dec2bn(&q, "67");
    BN_dec2bn(&e, "169");
    BN_dec2bn(&C, "1744");

    // Calculate n = p*q
    n = BN_new();
    BN_mul(n, p, q, ctx);
    printBN("n =", n);

    // Calculate d
    d = compute_d(p, q, e, ctx);
    printBN("d =", d);

    // Calculate M = C^d mod n
    M = decrypt(C, d, n, ctx);
    printBN("M =", M);

    printf("\n");

    /* Problem 4: Verify signature S = 1459 using values from Problem 3 */
    printf("Problem 4: Using values from Problem 3, verify signature S = 1459\n");
    S = BN_new();
    BN_dec2bn(&S, "1459");

    // To verify: check if M = S^e mod n
    int verified = verify_signature(M, S, e, n, ctx);
    if (verified) {
        printf("Signature is valid: S^e mod n = M\n");
    } else {
        printf("Signature is invalid: S^e mod n != M\n");

        // Show the value of S^e mod n
        BIGNUM *calculated_M = BN_new();
        BN_mod_exp(calculated_M, S, e, n, ctx);
        printBN("S^e mod n =", calculated_M);
        BN_free(calculated_M);
    }

    // Clean up
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(M);
    BN_free(C);
    BN_free(S);
    BN_free(phi);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_CTX_free(ctx);

    return 0;
}
