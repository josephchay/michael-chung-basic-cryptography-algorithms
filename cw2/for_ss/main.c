#include <string.h>
#include <openssl/bn.h>

void RSA_Question_1_d() {
    // Initialise pointers
    BIGNUM *d = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *exp = BN_new();
    BIGNUM *result = BN_new();

    // Convert decimal string to BN
    BN_dec2bn(&mod, "6720");
    BN_dec2bn(&exp, "143");

    // Compute modular inverse
    BN_mod_inverse(result, exp, mod, BN_CTX_new());

    // Convert BN to decimal string
    char *d_str = BN_bn2dec(result);
    printf("RSA Question 1: d = %s\n", d_str);

    // Free memory
    BN_free(d);
    BN_free(mod);
    BN_free(exp);
    BN_free(result);
}

void RSA_Question_1_C() {
    // Initialize pointers
    BIGNUM *C = BN_new();
    BIGNUM *base = BN_new();
    BIGNUM *exp = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *result = BN_new();

    // Convert decimal string to BN
    BN_dec2bn(&base, "1234");
    BN_dec2bn(&exp, "143");
    BN_dec2bn(&mod, "6887");

    // Calculate the modular exponent
    BN_mod_exp(result, base, exp, mod, BN_CTX_new());

    // Convert BN to decimal string
    char *c_str = BN_bn2dec(result);
    printf("RSA Question 1: C = %s\n", c_str);

    // Free memory
    BN_free(C);
    BN_free(base);
    BN_free(exp);
    BN_free(mod);
    BN_free(result);
}

void RSA_Question_2_e() {
    // Initialize pointers
    BIGNUM *e = BN_new();
    BIGNUM *base = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *result = BN_new();

    // Convert decimal string to BN
    BN_dec2bn(&base, "29401");
    BN_dec2bn(&mod, "68820");
    BN_dec2bn(&one, "1");

    // Calculate the modular inverse
    BN_mod_inverse(result, base, mod, BN_CTX_new());

    // Convert BN to decimal string
    char *e_str = BN_bn2dec(result);
    printf("RSA Question 2: e = %s\n", e_str);

    // Free memory
    BN_free(e);
    BN_free(base);
    BN_free(mod);
    BN_free(one);
    BN_free(result);
}

void RSA_Question_2_C() {
    // Initialize pointers
    BIGNUM *C1 = BN_new();
    BIGNUM *base = BN_new();
    BIGNUM *exp = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *result = BN_new();

    // Convert decimal string to BN
    BN_dec2bn(&base, "12345");
    BN_dec2bn(&exp, "4321");
    BN_dec2bn(&mod, "69353");

    // Calculate the modular exponent
    BN_mod_exp(result, base, exp, mod, BN_CTX_new());

    // Convert BN to decimal string
    char *c_str = BN_bn2dec(result);
    printf("RSA Question 2: C = %s\n", c_str);

    // Free memory
    BN_free(C1);
    BN_free(base);
    BN_free(exp);
    BN_free(mod);
    BN_free(result);
}

void RSA_Question_3_d() {
    // Initialize pointers
    BIGNUM *d = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *val = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *result = BN_new();

    // Convert decimal string to BN
    BN_dec2bn(&mod, "2376");
    BN_dec2bn(&val, "169");

    // Calculate the modular inverse
    BN_dec2bn(&one, "1");
    BN_mod_inverse(result, val, mod, BN_CTX_new());
    
    // Convert BN to decimal string
    char *d_str = BN_bn2dec(result);
    printf("RSA Question 3: d = %s\n", d_str);

    // Free memory
    BN_free(d);
    BN_free(mod);
    BN_free(val);
    BN_free(one);
    BN_free(result);
}

void RSA_Question_3_M() {
    // Initialise pointers
    BIGNUM *C = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *M = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // Convert decimal string to BN
    BN_dec2bn(&C, "1744");
    BN_dec2bn(&d, "2137");
    BN_dec2bn(&n, "2479");
    
    // M = C^d mod n
    BN_mod_exp(M, C, d, n, ctx);
    
    // Convert BN to decimal string
    char *M_str = BN_bn2dec(M);
    printf("RSA Question 3: M = %s\n", M_str);
    
    // Free memory
    BN_free(C);
    BN_free(d);
    BN_free(n);
    BN_free(M);
    BN_CTX_free(ctx);
}

void RSA_Question_4() {
    // Initialise pointers
    BIGNUM *S = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *M_prime = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // Convert decimal string to BN
    BN_dec2bn(&S, "1459");
    BN_dec2bn(&e, "169");
    BN_dec2bn(&n, "2479");
    
    // Calculate M' = S^e mod n
    BN_mod_exp(M_prime, S, e, n, ctx);
    
    // Convert BN to decimal string
    char *M_prime_str = BN_bn2dec(M_prime);
    printf("RSA Question 4: M' = %s\n", M_prime_str);
    
    if (strcmp(M_prime_str, "1234") == 0) {
        printf("M and M' are the same, S = 1459 is valid.\n");
    } else {
        printf("M and M' are not the same, S = 1459 is invalid.\n");
    }
    
    // Free memory
    BN_free(S);
    BN_free(e);
    BN_free(n);
    BN_free(M_prime);
    BN_CTX_free(ctx);
}

void Diffie_Hellman() {
    // Initialize pointers
    BIGNUM *ya = BN_new();
    BIGNUM *yb = BN_new();
    BIGNUM *Kab = BN_new();
    BIGNUM *base = BN_new();
    BIGNUM *exp_a = BN_new();
    BIGNUM *exp_b = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *result = BN_new();

    // Convert decimal string to BN
    BN_dec2bn(&base, "200");
    BN_dec2bn(&mod, "773");

    // Calculate ya = base^a mod p
    BN_dec2bn(&exp_a, "333");
    BN_mod_exp(ya, base, exp_a, mod, BN_CTX_new());
    char *first_ya_str = BN_bn2dec(ya);
    printf("Diffie Hellman Question 1: ya = %s\n", first_ya_str);

    // Calculate yb = base^b mod p
    BN_dec2bn(&exp_b, "603");
    BN_mod_exp(yb, base, exp_b, mod, BN_CTX_new());
    char *first_yb_str = BN_bn2dec(yb);
    printf("Diffie Hellman Question 1: yb = %s\n", first_yb_str);

    // Calculate Kab = ya^a mod p
    BN_dec2bn(&exp_a, "603"); 
    BN_mod_exp(Kab, ya, exp_a, mod, BN_CTX_new());
    char *first_Kab_str = BN_bn2dec(Kab);
    printf("Diffie Hellman Question 1: Kab = %s\n", first_Kab_str);

    // Convert decimal string to BN
    BN_dec2bn(&base, "307");
    BN_dec2bn(&mod, "1553");

    // Calculate ya = base^a mod p
    BN_dec2bn(&exp_a, "1333");
    BN_mod_exp(ya, base, exp_a, mod, BN_CTX_new());
    char *second_ya_str = BN_bn2dec(ya);
    printf("Diffie Hellman Question 2: ya = %s\n", second_ya_str);

    // Calculate yb = base^b mod p
    BN_dec2bn(&exp_b, "807");
    BN_mod_exp(yb, base, exp_b, mod, BN_CTX_new());
    char *second_yb_str = BN_bn2dec(yb);
    printf("Diffie Hellman Question 2: yb = %s\n", second_yb_str);

    // Calculate Kab = ya^a mod p
    BN_dec2bn(&exp_a, "807");
    BN_mod_exp(Kab, ya, exp_a, mod, BN_CTX_new());
    char *second_Kab_str = BN_bn2dec(Kab);
    printf("Diffie Hellman Question 2: Kab = %s\n", second_Kab_str);
    
    // Free memory
    BN_free(ya);
    BN_free(yb);
    BN_free(Kab);
    BN_free(base);
    BN_free(exp_a);
    BN_free(exp_b);
    BN_free(mod);
    BN_free(result);
}

void El_Gamal() {
    // Initialize pointers
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *xa = BN_new();
    BIGNUM *xb = BN_new();
    BIGNUM *ya = BN_new();
    BIGNUM *yb = BN_new();
    BIGNUM *K = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *C1 = BN_new();
    BIGNUM *C2 = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *result = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // Convert decimal string to BN
    BN_dec2bn(&p, "773");
    BN_dec2bn(&g, "200");
    BN_dec2bn(&xa, "333");
    BN_dec2bn(&xb, "603");
    BN_dec2bn(&M, "321");

    // Calculate ya = g^xa mod p
    BN_mod_exp(ya, g, xa, p, ctx);

    // Calculate yb = g^xb mod p
    BN_mod_exp(yb, g, xb, p, ctx);

    // Calculate K = ya^xb mod p
    BN_mod_exp(K, ya, xb, p, ctx);
    printf("El-Gamal Question 1: K = %s\n", BN_bn2dec(K));

    // Calculate C1 = g^xb mod p
    BN_mod_exp(C1, g, xb, p, ctx);
    printf("El-Gamal Question 1: C1 = %s\n", BN_bn2dec(C1));

    // Calculate C2 = (M * K) mod p
    BN_mod_mul(C2, M, K, p, ctx);
    printf("El-Gamal Question 1: C2 = %s\n", BN_bn2dec(C2));

    // Convert decimal string to BN
    BN_dec2bn(&p, "6469");
    BN_dec2bn(&g, "5055");
    BN_dec2bn(&xa, "2256");
    BN_dec2bn(&xb, "4127");
    BN_dec2bn(&C1, "3533");
    BN_dec2bn(&C2, "3719");

    // Calculate ya = g^xa mod p
    BN_mod_exp(ya, g, xa, p, ctx);

    // Calculate yb = g^xb mod p
    BN_mod_exp(yb, g, xb, p, ctx);

    // Calculate K = ya^xb mod p
    BN_mod_exp(K, ya, xb, p, ctx);
    printf("El-Gamal Question 2: K = %s\n", BN_bn2dec(K));

    // Calculate M = C2 / K mod p
    BN_mod_inverse(K, K, p, ctx);
    BN_mod_mul(M, C2, K, p, ctx);
    printf("El-Gamal Question 2: M = %s\n", BN_bn2dec(M));

    // Free memory
    BN_free(p);
    BN_free(g);
    BN_free(xa);
    BN_free(xb);
    BN_free(ya);
    BN_free(yb);
    BN_free(K);
    BN_free(M);
    BN_free(C1);
    BN_free(C2);
    BN_free(mod);
    BN_free(result);
    BN_CTX_free(ctx);
}

int main() {
    printf("Calculating the following tasks:\n");
    RSA_Question_1_d();
    RSA_Question_1_C();
    RSA_Question_2_e();
    RSA_Question_2_C();
    RSA_Question_3_d();
    RSA_Question_3_M();
    RSA_Question_4();
    Diffie_Hellman();
    El_Gamal();
    return 0;
}