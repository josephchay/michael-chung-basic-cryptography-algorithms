#include <stdio.h>
#include <openssl/bn.h>

// Utility function to print BIGNUM values
void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

// Calculate phi(n) = (p-1)(q-1)
BIGNUM* calculate_phi(BIGNUM *p, BIGNUM *q, BN_CTX *ctx) {
    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();

    BN_copy(p_minus_1, p);
    BN_copy(q_minus_1, q);
    BN_sub(p_minus_1, p_minus_1, BN_value_one());
    BN_sub(q_minus_1, q_minus_1, BN_value_one());
    BN_mul(phi, p_minus_1, q_minus_1, ctx);

    BN_free(p_minus_1);
    BN_free(q_minus_1);
    return phi;
}

// Calculate private key d = e^(-1) mod phi(n)
BIGNUM* calculate_private_key(BIGNUM *e, BIGNUM *phi, BN_CTX *ctx) {
    BIGNUM *d = BN_new();
    BN_mod_inverse(d, e, phi, ctx);
    return d;
}

// Calculate public key e = d^(-1) mod phi(n)
BIGNUM* calculate_public_key(BIGNUM *d, BIGNUM *phi, BN_CTX *ctx) {
    BIGNUM *e = BN_new();
    BN_mod_inverse(e, d, phi, ctx);
    return e;
}

// RSA encryption: C = M^e mod n
BIGNUM* encrypt_rsa(BIGNUM *M, BIGNUM *e, BIGNUM *n, BN_CTX *ctx) {
    BIGNUM *C = BN_new();
    BN_mod_exp(C, M, e, n, ctx);
    return C;
}

// RSA decryption: M = C^d mod n
BIGNUM* decrypt_rsa(BIGNUM *C, BIGNUM *d, BIGNUM *n, BN_CTX *ctx) {
    BIGNUM *M = BN_new();
    BN_mod_exp(M, C, d, n, ctx);
    return M;
}

// Verify RSA signature: returns 1 if valid, 0 if invalid
int verify_signature(BIGNUM *M, BIGNUM *S, BIGNUM *e, BIGNUM *n, BN_CTX *ctx) {
    BIGNUM *M_verify = BN_new();
    int result;

    printf("Steps:\n");
    printf("For signature verification, Bob needs to perform these operations:\n");
    printf("1. Compute M' = S^e mod n, specifically %s^%s mod %s\n",
           BN_bn2dec(S), BN_bn2dec(e), BN_bn2dec(n));
    printf("2. Verify whether M' matches the original message M\n");
    printf("A match between M' and M will confirm the signature's legitimacy and verifies Alice's authorship.\n\n");

    // M' = S^e mod n
    BN_mod_exp(M_verify, S, e, n, ctx);

    printBN("M' = ", M_verify);

    // Check if M' equals M
    result = (BN_cmp(M_verify, M) == 0);

    printf("Thus, the signature is %s! The message is %s from Alice.\n",
           result ? "valid" : "invalid",
           result ? "" : "not");

    BN_free(M_verify);
    return result;
}

// Solve RSA problem 1: find d and C given n, e, M
void solve_rsa1() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();

    BN_dec2bn(&n, "6887");
    BN_dec2bn(&e, "143");
    BN_dec2bn(&M, "1234");
    BN_dec2bn(&p, "71");
    BN_dec2bn(&q, "97");

    BIGNUM *phi = calculate_phi(p, q, ctx);
    BIGNUM *d = calculate_private_key(e, phi, ctx);
    BIGNUM *C = encrypt_rsa(M, e, n, ctx);

    printf("Problem 1:\n");
    printf("Decryption key (d) = %s\n", BN_bn2dec(d));
    printf("Ciphertext (C) = %s\n\n", BN_bn2dec(C));

    BN_free(n);
    BN_free(e);
    BN_free(M);
    BN_free(p);
    BN_free(q);
    BN_free(phi);
    BN_free(d);
    BN_free(C);
    BN_CTX_free(ctx);
}

// Solve RSA problem 2: find e and C given n, d, M
void solve_rsa2() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();

    BN_dec2bn(&n, "69353");
    BN_dec2bn(&d, "29401");
    BN_dec2bn(&M, "12345");
    BN_dec2bn(&p, "223");
    BN_dec2bn(&q, "311");

    BIGNUM *phi = calculate_phi(p, q, ctx);
    BIGNUM *e = calculate_public_key(d, phi, ctx);
    BIGNUM *C = encrypt_rsa(M, e, n, ctx);

    printf("Problem 2:\n");
    printf("Encryption key (e) = %s\n", BN_bn2dec(e));
    printf("Ciphertext (C) = %s\n\n", BN_bn2dec(C));

    BN_free(n);
    BN_free(d);
    BN_free(M);
    BN_free(p);
    BN_free(q);
    BN_free(phi);
    BN_free(e);
    BN_free(C);
    BN_CTX_free(ctx);
}

// Solve RSA problem 3: find d and M given p, q, e, C
// Solve RSA problem 4: verify signature S using values from Problem 3
void solve_rsa3_and_4() {
    // Solve together to avoid redundancy
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *S = BN_new();

    BN_dec2bn(&p, "37");
    BN_dec2bn(&q, "67");
    BN_dec2bn(&e, "169");
    BN_dec2bn(&C, "1744");
    BN_dec2bn(&S, "1459");

    BIGNUM *n = BN_new();
    BN_mul(n, p, q, ctx);

    BIGNUM *phi = calculate_phi(p, q, ctx);
    BIGNUM *d = calculate_private_key(e, phi, ctx);
    BIGNUM *M = decrypt_rsa(C, d, n, ctx);

    printf("Problem 3:\n");
    printf("Decryption key (d) = %s\n", BN_bn2dec(d));
    printf("Plaintext (M) = %s\n\n", BN_bn2dec(M));

    printf("Problem 4:\n");
    verify_signature(M, S, e, n, ctx);

    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(C);
    BN_free(S);
    BN_free(n);
    BN_free(phi);
    BN_free(d);
    BN_free(M);
    BN_CTX_free(ctx);
}

// RSA main function to solve problems
int main() {
    printf("\n=== RSA Problems Solutions ===\n");
    solve_rsa1();
    solve_rsa2();
    solve_rsa3_and_4();
    return 0;
}
