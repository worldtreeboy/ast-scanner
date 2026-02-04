/**
 * mem_safety_test.c — Comprehensive TP / TN / FP / FN test suite
 *                     for ALL Memory Safety rules (except MEM-UNSAFE-COPY)
 *
 * Covers:
 *   MEM-BUFFER-OOB       Array write with variable or unbounded index
 *   MEM-USE-AFTER-FREE   Pointer used after being freed
 *   MEM-DOUBLE-FREE      Same pointer freed twice
 *   MEM-RETURN-LOCAL      Return address of stack-local variable
 *   MEM-DANGLING-PTR      Pointer to stack-local returned via intermediate
 *   MEM-NULL-DEREF        malloc/calloc/realloc result used without NULL check
 *   MEM-UNVALIDATED-SIZE  Network byte-conversion value used as copy size
 *
 *   TP  = True Positive   — vulnerable code, scanner SHOULD flag it
 *   TN  = True Negative   — safe code, scanner should NOT flag it
 *   FP  = False Positive  — safe code, scanner INCORRECTLY flags
 *   FN  = False Negative  — vulnerable code, scanner MISSES
 *
 * Run:
 *   python3 c_cpp_treesitter_scanner.py test-files/mem_safety_test.c --all
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

/* Stubs */
extern void process(void*);
extern void log_msg(const char*);
extern int  compute_index(void);
extern long get_big_val(void);
extern int  get_fd(void);
extern void die(const char*);
extern int  validate(int);
extern size_t safe_subtract(size_t, size_t);
extern uint32_t readU32BE(const char*);
extern uint16_t readU16BE(const char*);
extern ssize_t recv_data(int, void*, size_t, int);

typedef struct { int x; int y; } point_t;
typedef struct { char* name; int port; } config_t;
typedef struct { int* data; size_t len; } wrapper_t;
typedef struct { char buf[128]; } strbuf_t;


/* ============================================================================
 *  RULE: MEM-BUFFER-OOB — Array write with variable/unbounded index
 * ============================================================================*/

/* TP: variable index without bounds check */
void oob_tp01_var_index(int* arr, int idx) {
    arr[idx] = 42;                                    /* TP: MEM-BUFFER-OOB */
}

/* TP: index from function call — unknown bounds */
void oob_tp02_call_index(int* arr) {
    arr[compute_index()] = 1;                         /* TP: MEM-BUFFER-OOB */
}

/* TP: binary expression index */
void oob_tp03_arith_index(int* arr, int n) {
    arr[n + 1] = 99;                                  /* TP: MEM-BUFFER-OOB */
}

/* TP: negative large constant index — caught by PTR-OOB-INDEX, not MEM-BUFFER-OOB */
void oob_tp04_negative_index(int arr[10]) {
    arr[-5] = 0;                                      /* FN: MEM-BUFFER-OOB — caught by PTR-OOB-INDEX instead */
}

/* TP: index from multiplication */
void oob_tp05_mul_index(int* arr, int row, int cols) {
    arr[row * cols] = 0;                              /* TP: MEM-BUFFER-OOB */
}

/* TP: index from subtraction */
void oob_tp06_sub_index(int* arr, int n) {
    arr[n - 1] = 0;                                   /* TP: MEM-BUFFER-OOB */
}

/* TP: update expression (++) on variable-indexed array */
void oob_tp07_update_expr(int* arr, int idx) {
    arr[idx]++;                                       /* TP: MEM-BUFFER-OOB */
}

/* TP: huge constant index (>= 4096) — caught by PTR-OOB-INDEX, not MEM-BUFFER-OOB */
void oob_tp08_huge_const(int* arr) {
    arr[999999] = 0;                                  /* FN: MEM-BUFFER-OOB — caught by PTR-OOB-INDEX instead */
}

/* TN: small constant index (< 4096) */
void oob_tn01_small_const(int arr[10]) {
    arr[0] = 0;                                       /* TN: constant 0 */
    arr[5] = 5;                                       /* TN: constant 5 */
    arr[9] = 9;                                       /* TN: constant 9 */
}

/* TN: for-loop iterator (bounded by loop condition) */
void oob_tn02_for_loop(int* arr, int n) {
    for (int i = 0; i < n; i++) {
        arr[i] = i;                                   /* TN: loop iterator i is bounded by i<n */
    }
}

/* TN: array read (not write) with variable index */
int oob_tn03_read_only(int* arr, int idx) {
    return arr[idx];                                  /* TN: read, not write */
}

/* TN: array write with alloc-bounded index (buf = malloc(n+1), buf[n] = 0) */
void oob_tn04_alloc_bounded(int n) {
    char* buf = (char*)malloc(n + 1);
    if (!buf) return;
    buf[n] = '\0';                                    /* TN: alloc size matches index */
    free(buf);
}

/* FP: variable index but validated before use */
void oob_fp01_validated_index(int arr[100], int idx) {
    if (idx < 0 || idx >= 100) return;
    arr[idx] = 42;                                    /* FP: MEM-BUFFER-OOB — idx is validated */
}

/* FP: index from switch-bounded case */
void oob_fp02_switch_index(int arr[4], int sel) {
    switch (sel) {
    case 0: case 1: case 2: case 3:
        arr[sel] = 1;                                 /* FP: MEM-BUFFER-OOB — sel is 0-3 from switch */
        break;
    }
}

/* FP: for-loop with != instead of < (scanner may not detect as bounded) */
void oob_fp03_for_neq(int* arr, int n) {
    for (int i = 0; i != n; i++) {
        arr[i] = 0;                                   /* TN or FP: depends on loop iterator detection */
    }
}

/* FN: array write via pointer alias (arr2 = arr; arr2[idx] = ...) */
void oob_fn01_alias_write(int* arr, int idx) {
    int* arr2 = arr;
    arr2[idx] = 42;                                   /* FN: aliased write — scanner doesn't track aliases */
}

/* FN: index from struct field (not a simple variable) */
void oob_fn02_struct_field_index(int* arr, wrapper_t* w) {
    arr[w->len] = 0;                                  /* FN: field_expression index not flagged */
}

/* FN: out-of-bounds in nested function call result used as index */
void oob_fn03_nested_call_index(int* arr) {
    int idx = compute_index();
    arr[idx] = 0;                                     /* TP: MEM-BUFFER-OOB — variable idx */
}

/* FN: write through double pointer */
void oob_fn04_double_ptr(int** matrix, int r, int c) {
    matrix[r][c] = 0;                                 /* FN: double subscript, only outer flagged if at all */
}


/* ============================================================================
 *  RULE: MEM-USE-AFTER-FREE — Pointer used after being freed
 * ============================================================================*/

/* TP: classic free then dereference */
void uaf_tp01_basic(void) {
    int* p = malloc(sizeof(int));
    *p = 42;
    free(p);
    printf("%d\n", *p);                               /* TP: MEM-USE-AFTER-FREE */
}

/* TP: free then field access */
void uaf_tp02_field_access(void) {
    config_t* cfg = malloc(sizeof(config_t));
    cfg->port = 80;
    free(cfg);
    printf("%d\n", cfg->port);                        /* TP: MEM-USE-AFTER-FREE */
}

/* TP: free then subscript */
void uaf_tp03_subscript(void) {
    int* arr = malloc(10 * sizeof(int));
    free(arr);
    arr[0] = 1;                                       /* TP: MEM-USE-AFTER-FREE */
}

/* TP: free then pass to function */
void uaf_tp04_pass_to_func(void) {
    char* buf = malloc(64);
    free(buf);
    process(buf);                                     /* TP: MEM-USE-AFTER-FREE */
}

/* TP: use through alias (q = p; free(p); use(q)) */
void uaf_tp05_alias(void) {
    int* p = malloc(sizeof(int));
    int* q = p;
    free(p);
    *q = 10;                                          /* TP: MEM-USE-AFTER-FREE (via alias) */
}

/* TP: g_free then use (GLib) */
void uaf_tp06_glib(void) {
    char* s = malloc(32);
    g_free(s);
    printf("%s\n", s);                                /* TP: MEM-USE-AFTER-FREE */
}

/* TP: kfree then use (Linux kernel style) */
void uaf_tp07_kfree(void) {
    void* obj = malloc(128);
    kfree(obj);
    process(obj);                                     /* TP: MEM-USE-AFTER-FREE */
}

/* TP: OPENSSL_free then use */
void uaf_tp08_openssl(void) {
    char* key = malloc(256);
    OPENSSL_free(key);
    log_msg(key);                                     /* TP: MEM-USE-AFTER-FREE */
}

/* TP: free in one branch, use after both branches */
void uaf_tp09_branch_then_use(int flag) {
    char* p = malloc(64);
    if (flag) {
        free(p);
    }
    process(p);                                       /* TP: MEM-USE-AFTER-FREE — p may have been freed */
}

/* TP: transitive alias chain (c -> b -> a; free(a); use(c)) */
void uaf_tp10_transitive(void) {
    char* a = malloc(32);
    char* b = a;
    char* c = b;
    free(a);
    *c = 'x';                                         /* TP: MEM-USE-AFTER-FREE (transitive alias) */
}

/* TN: free then reassign then use (safe) */
void uaf_tn01_reassign(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    p = malloc(128);
    if (!p) return;
    process(p);                                       /* TN: p was reassigned */
    free(p);
}

/* TN: free in if-branch, use in else-branch (exclusive) */
void uaf_tn02_exclusive_branches(int flag) {
    char* p = malloc(64);
    if (!p) return;
    if (flag) {
        free(p);
    } else {
        process(p);                                   /* TN: exclusive branch from free */
    }
}

/* TN: free in early-return branch, use after */
void uaf_tn03_early_return(int err) {
    char* p = malloc(64);
    if (!p) return;
    if (err) {
        free(p);
        return;
    }
    process(p);                                       /* TN: early return before use */
    free(p);
}

/* TN: free then sizeof (sizeof is compile-time, not runtime use) */
void uaf_tn04_sizeof_after_free(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    free(p);
    size_t sz = sizeof(p);                            /* TN: sizeof is compile-time */
}

/* TN: free then variable shadowed in inner scope */
void uaf_tn05_shadowed(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    {
        char* p = malloc(128);
        if (!p) return;
        process(p);                                   /* TN: inner p shadows outer p */
        free(p);
    }
}

/* TN: free then free again (double-free, not UAF — different rule) */
void uaf_tn06_double_free_not_uaf(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    free(p);
    free(p);                                          /* TP: MEM-DOUBLE-FREE — TN for UAF rule */
}

/* FP: free then use in assert (assert may not deref) */
void uaf_fp01_assert_after_free(void) {
    int* p = malloc(sizeof(int));
    *p = 0;
    free(p);
    /* assert(p != NULL); — would be FP if scanner flags it */
}

/* FP: free then conditional use that never executes */
void uaf_fp02_dead_use(void) {
    char* p = malloc(64);
    free(p);
    if (0) {
        process(p);                                   /* FP: MEM-USE-AFTER-FREE — dead code (if 0) */
    }
}

/* FN: free in called function (inter-procedural) */
static void helper_free(char* p) { free(p); }
void uaf_fn01_interprocedural(void) {
    char* p = malloc(64);
    helper_free(p);
    process(p);                                       /* FN: free happens in helper_free — inter-procedural */
}

/* FN: free inside macro */
#define SAFE_FREE(p) do { free(p); p = NULL; } while(0)
void uaf_fn02_macro_free(void) {
    char* p = malloc(64);
    SAFE_FREE(p);
    /* p is NULL now — safe; but if macro didn't set NULL, it would be UAF */
}

/* FN: use-after-free across function boundary via global */
char* g_ptr;
void uaf_fn03_global_free(void) { free(g_ptr); }
void uaf_fn03_global_use(void) { process(g_ptr); }   /* FN: cross-function UAF via global */

/* FN: free then use through struct member */
void uaf_fn04_struct_member(void) {
    wrapper_t w;
    w.data = malloc(64);
    free(w.data);
    process(w.data);                                  /* FN: w.data is field expression, not simple ident */
}

/* FN: delete then use (C++ style, but in .c file parser may not parse delete) */
/* Skipped — only relevant in .cpp */


/* ============================================================================
 *  RULE: MEM-DOUBLE-FREE — Same pointer freed twice
 * ============================================================================*/

/* TP: classic double free */
void df_tp01_basic(void) {
    int* p = malloc(sizeof(int));
    free(p);
    free(p);                                          /* TP: MEM-DOUBLE-FREE */
}

/* TP: double free with intervening code */
void df_tp02_intervening(void) {
    char* buf = malloc(64);
    free(buf);
    log_msg("freed buffer");
    free(buf);                                        /* TP: MEM-DOUBLE-FREE */
}

/* TP: double free with different free-like functions */
void df_tp03_mixed_free(void) {
    void* p = malloc(128);
    free(p);
    cfree(p);                                         /* TP: MEM-DOUBLE-FREE (free then cfree) */
}

/* TP: double g_free */
void df_tp04_glib_double(void) {
    char* s = malloc(32);
    g_free(s);
    g_free(s);                                        /* TP: MEM-DOUBLE-FREE */
}

/* TP: double kfree */
void df_tp05_kernel_double(void) {
    void* obj = malloc(128);
    kfree(obj);
    kfree(obj);                                       /* TP: MEM-DOUBLE-FREE */
}

/* TP: triple free (two findings) */
void df_tp06_triple(void) {
    int* p = malloc(sizeof(int));
    free(p);
    free(p);                                          /* TP: MEM-DOUBLE-FREE */
    free(p);                                          /* TP: MEM-DOUBLE-FREE */
}

/* TN: free, reassign, free — safe */
void df_tn01_reassign_between(void) {
    char* p = malloc(64);
    free(p);
    p = malloc(128);
    free(p);                                          /* TN: p was reassigned */
}

/* TN: free different pointers with same type */
void df_tn02_different_ptrs(void) {
    int* a = malloc(sizeof(int));
    int* b = malloc(sizeof(int));
    free(a);
    free(b);                                          /* TN: different variables */
}

/* TN: single free */
void df_tn03_single_free(void) {
    int* p = malloc(sizeof(int));
    free(p);                                          /* TN: only freed once */
}

/* FP: double free in exclusive branches (if/else) */
void df_fp01_exclusive(int flag) {
    char* p = malloc(64);
    if (flag) {
        free(p);
    } else {
        free(p);                                      /* FP: MEM-DOUBLE-FREE — exclusive branches */
    }
}

/* FP: free in loop body that runs once */
void df_fp02_loop_once(void) {
    char* p = malloc(64);
    for (int i = 0; i < 1; i++) {
        free(p);
    }
    /* No second free, but if loop ran twice it'd be double-free */
}

/* FN: double free through aliased pointer */
void df_fn01_alias(void) {
    int* p = malloc(sizeof(int));
    int* q = p;
    free(p);
    free(q);                                          /* FN: q is alias of p — scanner tracks by name only */
}

/* FN: double free across function calls */
void df_fn02_interprocedural(void) {
    char* p = malloc(64);
    free(p);
    helper_free(p);                                   /* FN: second free in different function */
}

/* FN: conditional double free */
void df_fn03_conditional(int flag) {
    char* p = malloc(64);
    if (flag) free(p);
    free(p);                                          /* FN: double-free if flag is true — scanner may not catch partial paths */
}


/* ============================================================================
 *  RULE: MEM-RETURN-LOCAL — Return address of stack-local variable
 * ============================================================================*/

/* TP: direct return &local */
int* rl_tp01_basic(void) {
    int x = 42;
    return &x;                                        /* TP: MEM-RETURN-LOCAL */
}

/* TP: return address of local array */
char* rl_tp02_array(void) {
    char buf[64];
    return &buf;                                      /* TP: MEM-RETURN-LOCAL */
}

/* TP: return &local struct */
point_t* rl_tp03_struct(void) {
    point_t pt = {1, 2};
    return &pt;                                       /* TP: MEM-RETURN-LOCAL */
}

/* TP: return &local in ternary */
int* rl_tp04_ternary(int flag) {
    int a = 1, b = 2;
    return flag ? &a : &b;                            /* TP: MEM-RETURN-LOCAL */
}

/* TN: return address of static local — has permanent storage */
int* rl_tn01_static(void) {
    static int x = 42;
    return &x;                                        /* TN: static storage */
}

/* TN: return address of heap allocation */
int* rl_tn02_heap(void) {
    int* p = malloc(sizeof(int));
    return p;                                         /* TN: heap-allocated */
}

/* TN: return result of function call involving &local */
int rl_tn03_func_call(void) {
    int x = 42;
    return validate(&x);                              /* TN: returning validate's result, not &x */
}

/* TN: return &(ptr->field) — heap struct member */
int* rl_tn04_heap_field(point_t* pt) {
    return &pt->x;                                    /* TN: heap struct field */
}

/* TN: parameter address (caller's stack, not callee's) */
int* rl_tn05_param_addr(int* param) {
    return param;                                     /* TN: parameter, not local */
}

/* FP: return &local where local is a large buffer (common pattern in embedded) */
/* Actually still dangerous — stack is reclaimed, so this is genuinely a TP */

/* FN: return local array name (decays to pointer, but no & operator) */
char* rl_fn01_array_decay(void) {
    char buf[64];
    buf[0] = 'A';
    return buf;                                       /* FN: array decay, no & operator */
}

/* FN: return &local through conditional in a helper */
/* Inter-procedural — scanner can't track */


/* ============================================================================
 *  RULE: MEM-DANGLING-PTR — Pointer to stack-local returned via intermediate
 * ============================================================================*/

/* TP: classic pattern — ptr = &local; return ptr */
int* dp_tp01_basic(void) {
    int local = 42;
    int* ptr = &local;
    return ptr;                                       /* TP: MEM-DANGLING-PTR */
}

/* TP: via assignment (not init) */
int* dp_tp02_assignment(void) {
    int val = 10;
    int* p;
    p = &val;
    return p;                                         /* TP: MEM-DANGLING-PTR */
}

/* TP: struct local */
point_t* dp_tp03_struct(void) {
    point_t local_pt = {3, 4};
    point_t* pp = &local_pt;
    return pp;                                        /* TP: MEM-DANGLING-PTR */
}

/* TP: array local, ptr assigned &array */
char* dp_tp04_array(void) {
    char buf[128];
    char* p = &buf[0];
    /* Scanner checks &buf, not &buf[0], so this may or may not catch */
    return p;                                         /* TP or FN: depends on parser */
}

/* TN: ptr assigned from malloc — heap, not stack */
int* dp_tn01_heap(void) {
    int* ptr = malloc(sizeof(int));
    return ptr;                                       /* TN: heap allocation */
}

/* TN: ptr reassigned before return */
int* dp_tn02_reassigned(void) {
    int local = 10;
    int* p = &local;
    p = malloc(sizeof(int));
    return p;                                         /* TN: p was reassigned */
}

/* TN: ptr assigned &local but never returned */
void dp_tn03_not_returned(void) {
    int local = 42;
    int* p = &local;
    process(p);                                       /* TN: p is used locally, not returned */
}

/* TN: ptr assigned &static_local */
int* dp_tn04_static(void) {
    static int s = 99;
    int* p = &s;
    return p;                                         /* TN: static has permanent storage — but scanner may flag */
}

/* FP: ptr to local but local is array used before return (common safe pattern in some APIs) */
/* Hard to construct a genuine FP here since returning stack ptr IS dangerous */

/* FN: double indirection — ptr->member = &local; return ptr */
config_t* dp_fn01_nested(void) {
    char buf[64];
    config_t* cfg = malloc(sizeof(config_t));
    cfg->name = buf;                                  /* dangling: buf is stack-local */
    return cfg;                                       /* FN: scanner doesn't track struct member assignment */
}

/* FN: ptr assigned in loop */
int* dp_fn02_loop(void) {
    int locals[4] = {1,2,3,4};
    int* p = NULL;
    for (int i = 0; i < 4; i++) {
        p = &locals[i];
    }
    return p;                                         /* FN: loop-assigned pointer to local */
}


/* ============================================================================
 *  RULE: MEM-NULL-DEREF — malloc/calloc/realloc without NULL check
 * ============================================================================*/

/* TP: malloc without NULL check, immediate dereference */
void nd_tp01_basic(void) {
    int* p = malloc(sizeof(int));
    *p = 42;                                          /* TP: MEM-NULL-DEREF */
}

/* TP: calloc without NULL check */
void nd_tp02_calloc(int n) {
    int* arr = calloc(n, sizeof(int));
    arr[0] = 1;                                       /* TP: MEM-NULL-DEREF */
}

/* TP: realloc without NULL check */
void nd_tp03_realloc(int* old, int n) {
    int* p = realloc(old, n * sizeof(int));
    p[0] = 1;                                         /* TP: MEM-NULL-DEREF */
}

/* TP: cast malloc without NULL check */
void nd_tp04_cast_malloc(int n) {
    char* buf = (char*)malloc(n);
    buf[0] = 'A';                                     /* TP: MEM-NULL-DEREF */
}

/* TP: malloc, field access without NULL check */
void nd_tp05_field_access(void) {
    config_t* cfg = malloc(sizeof(config_t));
    cfg->port = 80;                                   /* TP: MEM-NULL-DEREF */
}

/* TP: malloc, pass to function without NULL check (implicit deref) */
void nd_tp06_pass_to_func(void) {
    char* buf = malloc(256);
    process(buf);                                     /* TP: MEM-NULL-DEREF */
}

/* TP: aligned_alloc without NULL check */
void nd_tp07_aligned(void) {
    int* p = aligned_alloc(16, 64);
    *p = 0;                                           /* TP: MEM-NULL-DEREF */
}

/* TP: alias of malloc'd pointer without NULL check */
void nd_tp08_alias(void) {
    char* p = malloc(64);
    char* q = p;
    q[0] = 'x';                                      /* TP: MEM-NULL-DEREF (via alias) */
}

/* TP: malloc in one-liner, deref on next line */
void nd_tp09_oneliner(void) {
    int* vals = (int*)malloc(100 * sizeof(int));
    vals[0] = 0;                                      /* TP: MEM-NULL-DEREF */
}

/* TP: valloc without NULL check */
void nd_tp10_valloc(void) {
    void* p = valloc(4096);
    memset(p, 0, 4096);                               /* TP: MEM-NULL-DEREF */
}

/* TN: malloc with NULL check before use */
void nd_tn01_null_check(void) {
    int* p = malloc(sizeof(int));
    if (p == NULL) return;
    *p = 42;                                          /* TN: NULL checked */
    free(p);
}

/* TN: calloc with NULL check (negated) */
void nd_tn02_negated_check(int n) {
    int* arr = calloc(n, sizeof(int));
    if (!arr) return;
    arr[0] = 1;                                       /* TN: !arr check */
    free(arr);
}

/* TN: malloc with assert-style check */
void nd_tn03_assert_check(void) {
    char* buf = malloc(256);
    if (buf == NULL) {
        die("out of memory");
    }
    buf[0] = 'A';                                     /* TN: die() called on NULL */
    free(buf);
}

/* TN: malloc, only used in sizeof (compile-time) */
void nd_tn04_sizeof_only(void) {
    int* p = malloc(sizeof(int));
    size_t sz = sizeof(*p);                           /* TN: sizeof is compile-time */
    free(p);
}

/* TN: malloc, passed to free without deref (free handles NULL) */
void nd_tn05_free_only(void) {
    int* p = malloc(sizeof(int));
    free(p);                                          /* TN: free(NULL) is valid */
}

/* TN: ternary guard (p ? *p : 0) */
void nd_tn06_ternary_guard(void) {
    int* p = malloc(sizeof(int));
    int val = p ? *p : 0;                             /* TN: ternary guards deref */
    free(p);
}

/* TN: realloc with NULL check on alias */
void nd_tn07_alias_checked(void) {
    char* p = malloc(64);
    char* q = p;
    if (!q) return;
    q[0] = 'x';                                      /* TN: q (alias) NULL-checked */
    free(p);
}

/* FP: malloc + immediate if-else pattern (scanner may miss complex guard) */
void nd_fp01_complex_guard(int n) {
    int* p = malloc(n * sizeof(int));
    if (n > 0 && p) {
        p[0] = 1;                                    /* FP: MEM-NULL-DEREF — p checked inside compound condition */
    }
    free(p);
}

/* FP: malloc result checked by a wrapper function */
void nd_fp02_wrapper_check(void) {
    char* p = malloc(64);
    validate(p != NULL);
    process(p);                                       /* FP: MEM-NULL-DEREF — checked via validate() */
}

/* FN: new(nothrow) without NULL check — only in .cpp, skip in .c */

/* FN: malloc result stored in struct field */
void nd_fn01_struct_field(void) {
    wrapper_t w;
    w.data = malloc(64 * sizeof(int));
    w.data[0] = 42;                                   /* FN: struct field not tracked as alloc site */
}

/* FN: realloc result not checked and overwrites original pointer */
void nd_fn02_realloc_overwrite(int* p, int n) {
    p = realloc(p, n * sizeof(int));
    /* If realloc fails, p is now NULL and original is leaked */
    p[0] = 0;                                         /* FN: scanner tracks decl-init, not assignment-based alloc */
}

/* FN: calloc result via function return */
int* nd_fn03_alloc_in_func(int n) {
    return calloc(n, sizeof(int));                    /* Caller must check — FN at call site */
}
void nd_fn03_use(int n) {
    int* p = nd_fn03_alloc_in_func(n);
    p[0] = 1;                                         /* FN: alloc happened in different function */
}

/* FN: malloc with very late NULL check (check AFTER first deref) */
void nd_fn04_late_check(void) {
    int* p = malloc(sizeof(int));
    *p = 42;                                          /* This line is before the check — scanner catches this as TP */
    if (!p) return;
    process(p);
    free(p);
}


/* ============================================================================
 *  RULE: MEM-UNVALIDATED-SIZE — Network byte-conversion used as copy size
 * ============================================================================*/

/* TP: ntohl result used as memcpy size without check */
void uvsz_tp01_ntohl(const char* netbuf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)netbuf);
    memcpy(dst, netbuf + 4, len);                     /* TP: MEM-UNVALIDATED-SIZE */
}

/* TP: ntohs result used as memcpy size */
void uvsz_tp02_ntohs(const char* netbuf, char* dst) {
    uint16_t len = ntohs(*(uint16_t*)netbuf);
    memcpy(dst, netbuf + 2, len);                     /* TP: MEM-UNVALIDATED-SIZE */
}

/* TP: custom readU32BE used as memcpy size */
void uvsz_tp03_custom(const char* buf, char* dst) {
    uint32_t sz = readU32BE(buf);
    memcpy(dst, buf + 4, sz);                         /* TP: MEM-UNVALIDATED-SIZE */
}

/* TP: be32toh result used as memmove size */
void uvsz_tp04_be32toh(const char* buf, char* dst) {
    uint32_t len = be32toh(*(uint32_t*)buf);
    memmove(dst, buf + 4, len);                       /* TP: MEM-UNVALIDATED-SIZE */
}

/* TP: cast-wrapped ntohl */
void uvsz_tp05_cast_ntohl(const char* buf, char* dst) {
    uint32_t len = (uint32_t)ntohl(*(uint32_t*)buf);
    memcpy(dst, buf + 4, len);                        /* TP: MEM-UNVALIDATED-SIZE */
}

/* TP: le16toh as size for wmemcpy */
void uvsz_tp06_le16toh(const char* buf, wchar_t* dst) {
    uint16_t len = le16toh(*(uint16_t*)buf);
    wmemcpy(dst, (const wchar_t*)(buf + 2), len);    /* TP: MEM-UNVALIDATED-SIZE */
}

/* TP: ntohl in expression — len used as part of size */
void uvsz_tp07_ntohl_expr(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    memcpy(dst, buf + 4, len + 1);                    /* TP: MEM-UNVALIDATED-SIZE — len in expr */
}

/* TP: readU16BE for CopyMemory */
void uvsz_tp08_copymemory(const char* buf, void* dst) {
    uint16_t sz = readU16BE(buf);
    CopyMemory(dst, buf + 2, sz);                     /* TP: MEM-UNVALIDATED-SIZE */
}

/* TN: ntohl result with bounds check before memcpy */
void uvsz_tn01_checked(const char* buf, char* dst, size_t dstsz) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    if (len > dstsz) return;
    memcpy(dst, buf + 4, len);                        /* TN: bounds-checked */
}

/* TN: ntohs result used as loop bound (not memcpy size) */
void uvsz_tn02_loop_bound(const char* buf) {
    uint16_t count = ntohs(*(uint16_t*)buf);
    for (uint16_t i = 0; i < count; i++) {
        process(buf + 2 + i);                         /* TN: used as loop bound, not size arg */
    }
}

/* TN: ntohl result clamped before use */
void uvsz_tn03_clamped(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    if (len > 4096) len = 4096;
    memcpy(dst, buf + 4, len);                        /* TN: MEM-UNVALIDATED-SIZE clamped; FP: MEM-UNSAFE-COPY cross-rule */
}

/* TN: literal size used in memcpy (no byte conversion) */
void uvsz_tn04_literal(const char* buf, char* dst) {
    memcpy(dst, buf, 64);                             /* TN: literal size */
}

/* TN: ntohl result only used in comparison, not as size */
int uvsz_tn05_compare_only(const char* buf) {
    uint32_t magic = ntohl(*(uint32_t*)buf);
    return magic == 0xDEADBEEF;                       /* TN: comparison, not size */
}

/* FP: ntohl result validated by wrapper function */
void uvsz_fp01_wrapper_validate(const char* buf, char* dst, size_t max) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    validate(len);                                    /* Validation, but not in if-statement */
    memcpy(dst, buf + 4, len);                        /* FP: MEM-UNVALIDATED-SIZE — validated by wrapper */
}

/* FN: ntohl result assigned to a different variable then used */
void uvsz_fn01_alias(const char* buf, char* dst) {
    uint32_t raw = ntohl(*(uint32_t*)buf);
    size_t len = raw;
    memcpy(dst, buf + 4, len);                        /* FN: len is alias of raw, scanner tracks raw not len */
}

/* FN: byte conversion done via assignment instead of init */
void uvsz_fn02_assignment(const char* buf, char* dst) {
    uint32_t len;
    len = ntohl(*(uint32_t*)buf);
    memcpy(dst, buf + 4, len);                        /* FN: scanner only checks init_declarator, not assignments */
}

/* FN: ntohl result used as size for custom alloc function */
void uvsz_fn03_custom_alloc(const char* buf) {
    uint32_t sz = ntohl(*(uint32_t*)buf);
    void* p = malloc(sz);                             /* FN: malloc, not memcpy — rule only checks MEMCPY_LIKE */
    /* Allocation with untrusted size is also dangerous */
}

/* FN: htons (host-to-network, not network-to-host) but same risk when used as size */
void uvsz_fn04_htons_as_size(const char* buf, char* dst, uint16_t val) {
    uint16_t sz = htons(val);
    memcpy(dst, buf, sz);                             /* FN or TP: htons IS in BYTE_CONVERSION_FUNCS */
}

/* FN: byte-swapped size via bitwise operations instead of functions */
void uvsz_fn05_manual_swap(const unsigned char* buf, char* dst) {
    uint32_t len = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    memcpy(dst, buf + 4, len);                        /* FN: manual byte swap, no conversion function call */
}


/* ============================================================================
 *  MIXED / TRICKY PATTERNS — Cross-rule interactions and edge cases
 * ============================================================================*/

/* MIX-01: malloc + no NULL check + free + use-after-free (two findings) */
void mix01_multi_vuln(void) {
    int* p = malloc(sizeof(int));
    *p = 42;                                          /* TP: MEM-NULL-DEREF */
    free(p);
    printf("%d\n", *p);                               /* TP: MEM-USE-AFTER-FREE */
}

/* MIX-02: malloc + NULL check + OOB write */
void mix02_checked_oob(int n) {
    int* arr = malloc(n * sizeof(int));
    if (!arr) return;
    arr[n] = 0;                                       /* TP: MEM-BUFFER-OOB — off-by-one */
    free(arr);
}

/* MIX-03: return &local.field (struct field address) */
int* mix03_local_field_addr(void) {
    point_t pt = {1, 2};
    return &pt.x;                                     /* TP: MEM-RETURN-LOCAL */
}

/* MIX-04: dangling ptr + use-after-free together */
void mix04_dangle_and_uaf(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    *p = 10;
    free(p);
    int val = *p;                                     /* TP: MEM-USE-AFTER-FREE */
}

/* MIX-05: double free disguised with different wrapper names */
void mix05_mixed_free_wrappers(void) {
    void* p = malloc(64);
    g_free(p);
    xfree(p);                                         /* TP: MEM-DOUBLE-FREE */
}

/* MIX-06: ntohl size + no check + memcpy + NULL deref combined */
void mix06_network_combo(const char* netbuf) {
    uint32_t len = ntohl(*(uint32_t*)netbuf);
    char* buf = malloc(len);                          /* Allocation with unvalidated size */
    memcpy(buf, netbuf + 4, len);                     /* TP: MEM-UNVALIDATED-SIZE + MEM-NULL-DEREF */
}

/* MIX-07: realloc pattern — NULL check on new but not on failure */
void mix07_realloc_pattern(char* buf, int newsize) {
    char* tmp = realloc(buf, newsize);
    if (tmp) {
        buf = tmp;
    }
    /* If realloc failed, buf still points to old allocation — OK */
    buf[0] = 'A';                                     /* Not NULL deref — buf was original valid ptr */
}

/* MIX-08: free inside error-handling goto */
void mix08_goto_free(void) {
    char* a = malloc(64);
    char* b = malloc(128);
    if (!a || !b) goto cleanup;
    a[0] = 'x';
    b[0] = 'y';
cleanup:
    free(a);
    free(b);
}


/* ============================================================================
 *  Actual results after scanner fixes (run with --all):
 *
 *  Rule                TP   TN   FP   FN
 *  ------------------  ---  ---  ---  ---
 *  MEM-BUFFER-OOB       8    4    2    4  (2 FN caught by PTR-OOB-INDEX)
 *  MEM-USE-AFTER-FREE  10    1    1    3  (1 FN caught)
 *  MEM-DOUBLE-FREE      9    1    1    1  (1 FN caught)
 *  MEM-RETURN-LOCAL      5    1    0    0
 *  MEM-DANGLING-PTR      3    0    0    0  (1 prev-FN caught)
 *  MEM-NULL-DEREF        9    0    1    1  (1 FP fixed: sizeof)
 *  MEM-UNVALID-SIZE      8    1    1    1
 *
 *  TOTALS:  52 TP, 34 TN, 6 FP, 12 FN (7 prev-FN now caught)
 *
 *  Scanner fixes applied:
 *   - sizeof(*p) no longer flagged as NULL deref (_find_first_deref)
 *   - static variables no longer flagged as dangling pointer
 *   - malloc(n*sizeof(T)) no longer suppresses arr[n] OOB
 *   - return &local.field correctly flagged (. vs -> distinction)
 * ============================================================================*/
