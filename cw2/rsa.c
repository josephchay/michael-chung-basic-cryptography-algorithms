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

    // Return the verification result and the computed value
    printBN("Verification value (S^e mod n) =", M_verify);

    BN_free(M_verify);
    BN_CTX_free(ctx);

    return result;
}

void solve() {
    printf("\n========== RSA Problems Solutions ==========\n\n");
    BN_CTX *ctx = BN_CTX_new();

    // Problem 1: n=6887, e=143, M=1234, find d and C
    printf("Problem 1:\n");

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

    // Calculate phi(n) = (p-1)(q-1)
    BIGNUM *phi1 = BN_new();
    BIGNUM *p1_minus_1 = BN_new();
    BIGNUM *q1_minus_1 = BN_new();

    BN_copy(p1_minus_1, p1);
    BN_copy(q1_minus_1, q1);
    BN_sub(p1_minus_1, p1_minus_1, BN_value_one());
    BN_sub(q1_minus_1, q1_minus_1, BN_value_one());
    BN_mul(phi1, p1_minus_1, q1_minus_1, ctx);

    BIGNUM *d1 = calculate_private_key(p1, q1, e1);
    BIGNUM *C1 = encrypt(M1, e1, n1);

    printBN("p =", p1);
    printBN("q =", q1);
    printBN("n = p×q =", n1);
    printBN("φ(n) = (p-1)(q-1) =", phi1);
    printBN("e =", e1);
    printBN("d =", d1);
    printBN("M =", M1);
    printBN("C = M^e mod n =", C1);
    printf("\n");

    // Problem 2: n=69353, d=29401, M=12345, find e and C
    printf("Problem 2: n = 69353, e = ?, M = 12345, d = 29401, C = ?\n");
    printf("----------------------------------------------------\n");

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

    printBN("p =", p2);
    printBN("q =", q2);
    printBN("n = p×q =", n2);
    printBN("φ(n) = (p-1)(q-1) =", phi2);
    printBN("d =", d2);
    printBN("e = d^(-1) mod φ(n) =", e2);
    printBN("M =", M2);
    printBN("C = M^e mod n =", C2);
    printf("\n");

    // Problem 3: p=37, q=67, e=169, C=1744, find d and M
    printf("Problem 3: p = 37, q = 67, e = 169, M = ?, d = ?, C = 1744\n");
    printf("--------------------------------------------------------\n");

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

    // Calculate phi(n)
    BIGNUM *phi3 = BN_new();
    BIGNUM *p3_minus_1 = BN_new();
    BIGNUM *q3_minus_1 = BN_new();

    BN_copy(p3_minus_1, p3);
    BN_copy(q3_minus_1, q3);
    BN_sub(p3_minus_1, p3_minus_1, BN_value_one());
    BN_sub(q3_minus_1, q3_minus_1, BN_value_one());
    BN_mul(phi3, p3_minus_1, q3_minus_1, ctx);

    // Calculate d
    BIGNUM *d3 = calculate_private_key(p3, q3, e3);

    // Decrypt: M = C^d mod n
    BIGNUM *M3 = decrypt(C3, d3, n3);

    printBN("p =", p3);
    printBN("q =", q3);
    printBN("n = p×q =", n3);
    printBN("φ(n) = (p-1)(q-1) =", phi3);
    printBN("e =", e3);
    printBN("d = e^(-1) mod φ(n) =", d3);
    printBN("C =", C3);
    printBN("M = C^d mod n =", M3);
    printf("\n");

    // Problem 4: Verify signature S=1459 using values from Problem 3
    printf("Problem 4: Using values from Problem 3, verify signature S = 1459\n");
    printf("--------------------------------------------------------------\n");

    BIGNUM *S = BN_new();
    BN_dec2bn(&S, "1459");

    printf("To verify an RSA signature:\n");
    printf("1. Given: message M, signature S, public key (e,n)\n");
    printf("2. Compute: M' = S^e mod n\n");
    printf("3. If M' equals M, the signature is valid\n\n");

    printBN("M (from Problem 3) =", M3);
    printBN("S (signature) =", S);
    printBN("e (public exponent) =", e3);
    printBN("n (modulus) =", n3);

    int valid = verify_signature(M3, S, e3, n3);

    printf("\nSignature verification result: %s\n", valid ? "VALID" : "INVALID");

    if (valid) {
        printf("The signature is valid because S^e mod n equals M.\n");
        printf("This confirms that S was created using the private key d.\n");
    } else {
        printf("The signature is invalid because S^e mod n does not equal M.\n");
        printf("This means S was not created using the private key d.\n");
    }

    // Free all memory
    BN_free(n1); BN_free(e1); BN_free(M1); BN_free(p1); BN_free(q1);
    BN_free(d1); BN_free(C1); BN_free(phi1); BN_free(p1_minus_1); BN_free(q1_minus_1);

    BN_free(n2); BN_free(d2); BN_free(M2); BN_free(p2); BN_free(q2);
    BN_free(phi2); BN_free(e2); BN_free(C2); BN_free(p2_minus_1); BN_free(q2_minus_1);

    BN_free(p3); BN_free(q3); BN_free(e3); BN_free(C3); BN_free(n3);
    BN_free(d3); BN_free(M3); BN_free(phi3); BN_free(p3_minus_1); BN_free(q3_minus_1);

    BN_free(S);
    BN_CTX_free(ctx);
}

int main() {
    solve();
    return 0;
}
