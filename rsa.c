#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>


void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}


// Calculates the private key d given p, q, and e
BIGNUM* calculate_private_key(BIGNUM *p, BIGNUM *q, BIGNUM *e) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BIGNUM *d = BN_new();

    // Calculate φ(n) = (p-1)(q-1)
    BN_copy(p_minus_1, p);
    BN_copy(q_minus_1, q);
    BN_sub(p_minus_1, p_minus_1, BN_value_one());
    BN_sub(q_minus_1, q_minus_1, BN_value_one());
    BN_mul(phi, p_minus_1, q_minus_1, ctx);

    // Calculate d = e^(-1) mod φ(n)
    BN_mod_inverse(d, e, phi, ctx);

    BN_free(phi);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_CTX_free(ctx);

    return d;
}


// Encrypts a message using RSA: C = M^e mod n
BIGNUM* encrypt(BIGNUM *M, BIGNUM *e, BIGNUM *n) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *C = BN_new();

    // C = M^e mod n
    BN_mod_exp(C, M, e, n, ctx);

    BN_CTX_free(ctx);
    return C;
}


// Decrypts a ciphertext using RSA: M = C^d mod n
BIGNUM* decrypt(BIGNUM *C, BIGNUM *d, BIGNUM *n) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *M = BN_new();

    // M = C^d mod n
    BN_mod_exp(M, C, d, n, ctx);

    BN_CTX_free(ctx);
    return M;
}


// Verifies an RSA signature: returns 1 if valid, 0 if invalid
int verify_signature(BIGNUM *M, BIGNUM *S, BIGNUM *e, BIGNUM *n) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *M_verify = BN_new();
    int result;

    // M' = S^e mod n
    BN_mod_exp(M_verify, S, e, n, ctx);

    // Check if M' equals M
    result = (BN_cmp(M_verify, M) == 0);

    BN_free(M_verify);
    BN_CTX_free(ctx);

    return result;
}


void solve() {
    printf("\n========== RSA Problems Solutions ==========\n");
    BN_CTX *ctx = BN_CTX_new();

    // Problem 1: n=6887, e=143, M=1234, find d and C
    BIGNUM *n1 = BN_new();
    BIGNUM *e1 = BN_new();
    BIGNUM *M1 = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();

    BN_dec2bn(&n1, "6887");
    BN_dec2bn(&e1, "143");
    BN_dec2bn(&M1, "1234");

    // Known factorization: 6887 = 71 × 97
    BN_dec2bn(&p1, "71");
    BN_dec2bn(&q1, "97");

    BIGNUM *d1 = calculate_private_key(p1, q1, e1);
    BIGNUM *C1 = encrypt(M1, e1, n1);

    printf("Problem 1: n = 6887, e = 143, M = 1234, d = ?, C = ?\n");
    printBN("d =", d1);
    printBN("C =", C1);

    // Problem 2: n=69353, d=29401, M=12345, find e and C
    BIGNUM *n2 = BN_new();
    BIGNUM *d2 = BN_new();
    BIGNUM *M2 = BN_new();
    BIGNUM *p2 = BN_new();
    BIGNUM *q2 = BN_new();
    BIGNUM *phi2 = BN_new();
    BIGNUM *e2 = BN_new();

    BN_dec2bn(&n2, "69353");
    BN_dec2bn(&d2, "29401");
    BN_dec2bn(&M2, "12345");

    // Known factorization: 69353 = 223 × 311
    BN_dec2bn(&p2, "223");
    BN_dec2bn(&q2, "311");

    BIGNUM *p2_minus_1 = BN_new();
    BIGNUM *q2_minus_1 = BN_new();
    BN_copy(p2_minus_1, p2);
    BN_copy(q2_minus_1, q2);
    BN_sub(p2_minus_1, p2_minus_1, BN_value_one());
    BN_sub(q2_minus_1, q2_minus_1, BN_value_one());
    BN_mul(phi2, p2_minus_1, q2_minus_1, ctx);

    // Find e: e = d^(-1) mod φ(n)
    BN_mod_inverse(e2, d2, phi2, ctx);

    // Encrypt: C = M^e mod n
    BIGNUM *C2 = encrypt(M2, e2, n2);

    printf("Problem 2: n = 69353, e = ?, M = 12345, d = 29401, C = ?\n");
    printBN("e =", e2);
    printBN("C =", C2);

    // Problem 3: p=37, q=67, e=169, C=1744, find d and M
    BIGNUM *p3 = BN_new();
    BIGNUM *q3 = BN_new();
    BIGNUM *e3 = BN_new();
    BIGNUM *C3 = BN_new();

    BN_dec2bn(&p3, "37");
    BN_dec2bn(&q3, "67");
    BN_dec2bn(&e3, "169");
    BN_dec2bn(&C3, "1744");

    // Calculate n = p×q
    BIGNUM *n3 = BN_new();
    BN_mul(n3, p3, q3, ctx);

    // Calculate d
    BIGNUM *d3 = calculate_private_key(p3, q3, e3);

    // Decrypt: M = C^d mod n
    BIGNUM *M3 = decrypt(C3, d3, n3);

    printf("Problem 3: p = 37, q = 67, e = 169, M = ?, d = ?, C = 1744\n");
    printBN("d =", d3);
    printBN("M =", M3);

    // Problem 4: Verify signature S=1459 using values from Problem 3
    BIGNUM *S = BN_new();
    BN_dec2bn(&S, "1459");

    int valid = verify_signature(M3, S, e3, n3);

    printf("Problem 4: Using values from Problem 3, verify signature S = 1459\n");
    printf("Signature is %s\n", valid ? "Valid" : "Invalid");

    // Free all memory
    BN_free(n1);
    BN_free(e1);
    BN_free(M1);
    BN_free(p1);
    BN_free(q1);
    BN_free(d1);
    BN_free(C1);
    BN_free(n2);
    BN_free(d2);
    BN_free(M2);
    BN_free(p2);
    BN_free(q2);
    BN_free(phi2);
    BN_free(e2);
    BN_free(C2);
    BN_free(p3);
    BN_free(q3);
    BN_free(e3);
    BN_free(C3);
    BN_free(n3);
    BN_free(d3);
    BN_free(M3);
    BN_free(S);
    BN_free(p2_minus_1);
    BN_free(q2_minus_1);
    BN_CTX_free(ctx);
}


int main() {
    solve();
    return 0;
}
