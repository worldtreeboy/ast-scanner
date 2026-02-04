/*
 * mem_safety_hard_test.c — Hard-to-detect test cases for memory safety rules
 *
 * These test cases target known scanner blind spots: indirect aliases, nested
 * scopes, struct members, conditional paths, cast chains, bitwise operations,
 * macro-like patterns, and edge cases in tree-sitter AST analysis.
 *
 * Annotation format (inline only):
 *   /* TP: RULE-ID — description */
 *   /* TN: RULE-ID — description */
 *   /* FP: RULE-ID — description */
 *   /* FN: RULE-ID — description */
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

/* Forward declarations / helpers */
extern void process(void*);
extern void consume(int);
extern int get_index(void);
extern int get_condition(void);
extern void* xmalloc(size_t);  /* never-fail allocator */
extern void my_cleanup(void*);
extern int is_valid(void*);
extern void handle_error(void);
extern void* get_next(void);
extern void log_msg(const char*);
extern uint32_t ntohl(uint32_t);
extern uint16_t ntohs(uint16_t);
extern uint32_t be32toh(uint32_t);
extern uint64_t be64toh(uint64_t);
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX_BUF 4096
#define SAFE_FREE(p) do { if(p) { free(p); (p) = NULL; } } while(0)
#define CHECK_SIZE(s) do { if((s) > MAX_BUF) return; } while(0)

typedef struct {
    int x;
    int y;
    struct { int z; } nested;
} point_t;

typedef struct {
    int* data;
    char* name;
    size_t len;
} container_t;

typedef struct node {
    struct node* next;
    int value;
} node_t;

static int g_idx = 9999;
static int g_global_var = 42;

/* ============================================================================
 *  SECTION 1: MEM-BUFFER-OOB — Hard cases
 * ============================================================================*/

/* --- Hard TP: should be caught --- */

/* OOB-H01: compound assignment (+=) with variable index */
void oob_h01_compound_assign(int* arr, int idx, int val) {
    arr[idx] += val;                                      /* TP: MEM-BUFFER-OOB — compound assign */
}

/* OOB-H02: write inside while-loop with unbounded index */
void oob_h02_while_unbounded(int* arr, int n) {
    int i = 0;
    while (i < n * 2) {
        arr[i] = 0;                                       /* TP: MEM-BUFFER-OOB — while loop unbounded */
        i += 3;  /* stride > 1, could skip past n */
    }
}

/* OOB-H03: ternary index expression */
void oob_h03_ternary_index(int* arr, int a, int b, int cond) {
    arr[cond ? a : b] = 1;                                /* TP: MEM-BUFFER-OOB — ternary index */
}

/* OOB-H04: index from subtraction (potential underflow) */
void oob_h04_sub_index(int* arr, int len, int offset) {
    arr[len - offset] = 0;                                /* TP: MEM-BUFFER-OOB — subtraction index */
}

/* OOB-H05: cast-to-pointer then index */
void oob_h05_cast_index(void* buf, int n) {
    ((int*)buf)[n] = 0;                                   /* TP: MEM-BUFFER-OOB — cast then index */
}

/* OOB-H06: index from function return value */
void oob_h06_funcall_index(int* arr) {
    arr[get_index()] = 42;                                /* TP: MEM-BUFFER-OOB — function return index */
}

/* OOB-H07: post-increment index in assignment */
void oob_h07_postinc(int* arr, int i, int val) {
    arr[i++] = val;                                       /* TP: MEM-BUFFER-OOB — post-increment */
}

/* OOB-H08: pre-decrement index */
void oob_h08_predec(int* arr, int i, int val) {
    arr[--i] = val;                                       /* TP: MEM-BUFFER-OOB — pre-decrement */
}

/* --- Hard TN: should NOT be caught --- */

/* OOB-H09: index masked by bitwise AND — always bounded */
void oob_h09_bitmask_tn(int* arr, int idx) {
    arr[idx & 0xFF] = 1;                                  /* FP: MEM-BUFFER-OOB — bitwise AND bounds to 256 */
}

/* OOB-H10: write guarded by if before same line */
void oob_h10_guarded_write(int* arr, int idx, int size) {
    if (idx < size)
        arr[idx] = 1;                                     /* FP: MEM-BUFFER-OOB — guarded by if */
}

/* OOB-H11: sizeof-derived index (always small) */
void oob_h11_sizeof_index(int arr[100]) {
    arr[sizeof(int)] = 99;                                /* TN: MEM-BUFFER-OOB — sizeof is constant 4 */
}

/* OOB-H12: enum constant used as index */
enum { IDX_FIRST = 0, IDX_SECOND = 1, IDX_LAST = 9 };
void oob_h12_enum_index(int arr[10]) {
    arr[IDX_LAST] = 42;                                   /* FP: MEM-BUFFER-OOB — enum constant looks like identifier */
}

/* OOB-H13: alloc-bounded via calloc(n+1, ...) */
void oob_h13_calloc_bounded(int n) {
    char* buf = calloc(n + 1, 1);
    if (!buf) return;
    buf[n] = '\0';                                        /* TN: MEM-BUFFER-OOB — calloc(n+1) bounds n */
}

/* OOB-H14: for-loop with <= (not <) — still bounded by loop */
void oob_h14_for_lte(int* arr, int n) {
    for (int i = 0; i <= n; i++)
        arr[i] = 0;                                       /* TN: MEM-BUFFER-OOB — for-loop iterator */
}

/* --- Hard FN: vulnerable but scanner misses --- */

/* OOB-H15: OOB read (not write) — scanner only checks writes */
int oob_h15_read_oob(int* arr, int user_idx) {
    return arr[user_idx];                                  /* FN: MEM-BUFFER-OOB — reads not detected */
}

/* OOB-H16: write through double pointer dereference */
void oob_h16_double_ptr(int** pp, int n) {
    (*pp)[n] = 0;                                         /* FN: MEM-BUFFER-OOB — double ptr deref */
}

/* OOB-H17: index from global variable */
void oob_h17_global_index(int* arr) {
    arr[g_idx] = 0;                                       /* FN: MEM-BUFFER-OOB — global index not tracked */
}

/* OOB-H18: VLA with unchecked size then write to last */
void oob_h18_vla(int n) {
    int vla[n];
    vla[n] = 0;                                           /* FN: MEM-BUFFER-OOB — off-by-one on VLA */
}

/* OOB-H19: write via pointer alias of array */
void oob_h19_ptr_alias(int n) {
    int arr[10];
    int* p = arr;
    p[n] = 0;                                             /* TP: MEM-BUFFER-OOB — ptr alias of array */
}

/* OOB-H20: modulo-bounded index (safe but complex) */
void oob_h20_modulo_bound(int* arr, int idx, int size) {
    arr[idx % size] = 1;                                  /* FP: MEM-BUFFER-OOB — modulo bounds it */
}

/* ============================================================================
 *  SECTION 2: MEM-USE-AFTER-FREE — Hard cases
 * ============================================================================*/

/* --- Hard TP: should be caught --- */

/* UAF-H01: free then pass to memset */
void uaf_h01_memset_after_free(void) {
    char* buf = malloc(256);
    if (!buf) return;
    free(buf);
    memset(buf, 0, 256);                                  /* TP: MEM-USE-AFTER-FREE — memset after free */
}

/* UAF-H02: transitive alias chain: a→b→c, free(a), use(c) */
void uaf_h02_deep_alias(void) {
    int* a = malloc(sizeof(int));
    if (!a) return;
    int* b = a;
    int* c = b;
    free(a);
    *c = 42;                                              /* TP: MEM-USE-AFTER-FREE — deep alias */
}

/* UAF-H03: free then pass as function argument */
void uaf_h03_pass_freed(void) {
    char* data = malloc(128);
    if (!data) return;
    free(data);
    process(data);                                        /* TP: MEM-USE-AFTER-FREE — pass freed ptr */
}

/* UAF-H04: free with intervening no-op code (no reassignment) */
void uaf_h04_noop_between(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    free(p);
    log_msg("freed");
    consume(42);
    *p = 10;                                              /* TP: MEM-USE-AFTER-FREE — noop between */
}

/* UAF-H05: kfree then field access */
void uaf_h05_kfree_field(void) {
    node_t* n = malloc(sizeof(node_t));
    if (!n) return;
    n->value = 1;
    kfree(n);
    consume(n->value);                                    /* TP: MEM-USE-AFTER-FREE — kfree then field */
}

/* UAF-H06: g_free then subscript */
void uaf_h06_gfree_subscript(void) {
    char* buf = malloc(64);
    if (!buf) return;
    g_free(buf);
    buf[0] = 'A';                                        /* TP: MEM-USE-AFTER-FREE — g_free then subscript */
}

/* UAF-H07: free inside nested braces, use outside */
void uaf_h07_nested_free(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    {
        free(p);
    }
    *p = 99;                                              /* TP: MEM-USE-AFTER-FREE — nested scope free */
}

/* UAF-H08: free via OPENSSL_free then pointer comparison */
void uaf_h08_openssl_cmp(void) {
    char* key = malloc(32);
    if (!key) return;
    OPENSSL_free(key);
    if (key != NULL)                                      /* TP: MEM-USE-AFTER-FREE — comparison after free */
        process(key);
}

/* --- Hard TN: should NOT be caught --- */

/* UAF-H09: free then reassign via strdup */
void uaf_h09_reassign_strdup(const char* s) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    p = strdup(s);
    if (p) process(p);                                    /* TN: MEM-USE-AFTER-FREE — reassigned */
    free(p);
}

/* UAF-H10: free in early-return error path, use after */
void uaf_h10_error_return(int* p, int ok) {
    if (!ok) {
        free(p);
        return;
    }
    *p = 42;                                              /* TN: MEM-USE-AFTER-FREE — exclusive paths */
}

/* UAF-H11: free in loop, reassign at top of next iteration */
void uaf_h11_loop_realloc(int count) {
    char* p = NULL;
    for (int i = 0; i < count; i++) {
        free(p);
        p = malloc(64);
        if (!p) return;
        p[0] = (char)i;                                  /* TN: MEM-USE-AFTER-FREE — reassigned in loop */
    }
    free(p);
}

/* UAF-H12: free, NULL assignment, conditional use on different allocation */
void uaf_h12_null_reset(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    p = NULL;
    p = malloc(128);
    if (p) p[0] = 'x';                                   /* TN: MEM-USE-AFTER-FREE — new allocation */
    free(p);
}

/* --- Hard FP: safe but scanner might flag --- */

/* UAF-H13: free inside if(0) dead code */
void uaf_h13_dead_code(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    if (0) {
        free(p);
    }
    *p = 42;                                              /* FP: MEM-USE-AFTER-FREE — if(0) is dead code */
    free(p);
}

/* UAF-H14: free inside unreachable code (after return) */
void uaf_h14_after_return(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    *p = 1;
    free(p);
    return;
    /* dead code below */
    process(p);                                           /* FP: MEM-USE-AFTER-FREE — unreachable after return */
}

/* --- Hard FN: vulnerable but scanner misses --- */

/* UAF-H15: UAF through struct member */
void uaf_h15_struct_member(void) {
    container_t c;
    c.data = malloc(sizeof(int) * 10);
    if (!c.data) return;
    free(c.data);
    c.data[0] = 42;                                       /* FN: MEM-USE-AFTER-FREE — struct member UAF */
}

/* UAF-H16: UAF via realloc failure (old ptr becomes dangling) */
void uaf_h16_realloc_fail(void) {
    char* p = malloc(64);
    if (!p) return;
    char* old = p;
    p = realloc(p, 1024 * 1024);
    if (p) {
        old[0] = 'x';                                    /* FN: MEM-USE-AFTER-FREE — old ptr dangling after realloc */
    }
}

/* UAF-H17: UAF through array element */
void uaf_h17_array_element(void) {
    char* ptrs[4];
    ptrs[0] = malloc(64);
    if (!ptrs[0]) return;
    free(ptrs[0]);
    ptrs[0][0] = 'A';                                    /* FN: MEM-USE-AFTER-FREE — array element */
}

/* UAF-H18: free wrapped in user function */
void uaf_h18_wrapper_free(void) {
    char* p = malloc(64);
    if (!p) return;
    my_cleanup(p);
    p[0] = 'x';                                          /* FN: MEM-USE-AFTER-FREE — custom free wrapper */
}

/* UAF-H19: UAF via callback pattern */
typedef void (*free_fn)(void*);
void uaf_h19_callback_free(void) {
    free_fn fn = free;
    char* p = malloc(64);
    if (!p) return;
    fn(p);
    p[0] = 'x';                                          /* FN: MEM-USE-AFTER-FREE — free via callback */
}

/* ============================================================================
 *  SECTION 3: MEM-DOUBLE-FREE — Hard cases
 * ============================================================================*/

/* --- Hard TP: should be caught --- */

/* DF-H01: double free with lots of intervening code */
void df_h01_long_gap(void) {
    char* p = malloc(128);
    if (!p) return;
    free(p);
    log_msg("step 1");
    consume(1);
    log_msg("step 2");
    consume(2);
    log_msg("step 3");
    free(p);                                              /* TP: MEM-DOUBLE-FREE — long gap */
}

/* DF-H02: free + cfree same pointer */
void df_h02_mixed_funcs(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    cfree(p);                                             /* TP: MEM-DOUBLE-FREE — free + cfree */
}

/* DF-H03: triple free */
void df_h03_triple(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    free(p);
    free(p);                                              /* TP: MEM-DOUBLE-FREE — second free */
    free(p);                                              /* TP: MEM-DOUBLE-FREE — third free */
}

/* DF-H04: double free with cast between */
void df_h04_cast_between(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    free(p);
    free((void*)p);                                       /* TP: MEM-DOUBLE-FREE — cast doesn't help */
}

/* DF-H05: g_free then free on same pointer */
void df_h05_gfree_free(void) {
    char* s = malloc(64);
    if (!s) return;
    g_free(s);
    free(s);                                              /* TP: MEM-DOUBLE-FREE — g_free + free */
}

/* DF-H06: free in nested scope then again outside */
void df_h06_nested_scope(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    {
        free(p);
    }
    free(p);                                              /* TP: MEM-DOUBLE-FREE — nested then outer */
}

/* --- Hard TN: should NOT be caught --- */

/* DF-H07: free, reassign to new alloc, free again */
void df_h07_reassign(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    p = malloc(128);
    free(p);                                              /* TN: MEM-DOUBLE-FREE — reassigned between */
}

/* DF-H08: SAFE_FREE sets to NULL, second free checks NULL */
void df_h08_safe_macro(void) {
    char* p = malloc(64);
    if (!p) return;
    SAFE_FREE(p);
    free(p);                                              /* TN: MEM-DOUBLE-FREE — SAFE_FREE nulls it */
}

/* DF-H09: free in one if-branch, different ptr in else */
void df_h09_diff_branches(int cond) {
    char* a = malloc(32);
    char* b = malloc(64);
    if (!a || !b) { free(a); free(b); return; }
    if (cond) {
        free(a);
    } else {
        free(b);
    }
    /* Only one is freed based on cond */
}

/* --- Hard FP: safe but scanner might flag --- */

/* DF-H10: free inside if(error), then free in cleanup with return between */
void df_h10_error_cleanup(int err) {
    char* p = malloc(64);
    if (!p) return;
    if (err) {
        free(p);
        return;
    }
    process(p);
    free(p);                                              /* FP: MEM-DOUBLE-FREE — error path returns */
}

/* DF-H11: free inside loop body (each iteration frees different alloc) */
void df_h11_loop_free(int n) {
    for (int i = 0; i < n; i++) {
        char* p = malloc(64);
        if (!p) continue;
        process(p);
        free(p);
    }
    /* No double-free: each p is a new allocation */
}

/* DF-H12: conditional free patterns — mutually exclusive conditions */
void df_h12_mutex_cond(int x) {
    char* p = malloc(64);
    if (!p) return;
    if (x > 0)
        free(p);                                          /* FP: MEM-DOUBLE-FREE — mutex separate ifs */
    if (x <= 0)
        free(p);                                          /* FP: MEM-DOUBLE-FREE — mutex separate ifs */
}

/* --- Hard FN: vulnerable but scanner misses --- */

/* DF-H13: aliased double-free: q=p, free(p), free(q) */
void df_h13_alias_df(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    int* q = p;
    free(p);
    free(q);                                              /* FN: MEM-DOUBLE-FREE — aliased double-free */
}

/* DF-H14: double free through struct member */
void df_h14_struct_df(void) {
    container_t c;
    c.data = malloc(sizeof(int) * 10);
    if (!c.data) return;
    free(c.data);
    free(c.data);                                         /* FN: MEM-DOUBLE-FREE — struct member */
}

/* DF-H15: double free via different alias names */
void df_h15_multi_alias(void) {
    void* base = malloc(128);
    if (!base) return;
    char* alias1 = (char*)base;
    int* alias2 = (int*)base;
    free(alias1);
    free(alias2);                                         /* FN: MEM-DOUBLE-FREE — cast aliases */
}

/* DF-H16: free in two called functions (inter-procedural) */
static void helper_free_it(void* p) { free(p); }
void df_h16_interprocedural(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    helper_free_it(p);
    free(p);                                              /* FN: MEM-DOUBLE-FREE — inter-procedural */
}

/* ============================================================================
 *  SECTION 4: MEM-RETURN-LOCAL — Hard cases
 * ============================================================================*/

/* --- Hard TP: should be caught --- */

/* RL-H01: return address of local array element */
int* rl_h01_array_element(void) {
    int arr[10] = {0};
    return &arr[0];                                       /* TP: MEM-RETURN-LOCAL — array element */
}

/* RL-H02: return address of deeply nested struct field */
point_t* rl_h02_nested_field(void) {
    point_t pt = {1, 2, {3}};
    return &pt;                                           /* TP: MEM-RETURN-LOCAL — struct address */
}

/* RL-H03: return &local via ternary (one branch bad) */
int g_static_val = 0;
int* rl_h03_ternary(int cond) {
    int local = 42;
    return cond ? &local : &g_static_val;                 /* TP: MEM-RETURN-LOCAL — ternary one branch bad */
}

/* RL-H04: return address of function parameter (by-value) */
int* rl_h04_param_addr(int param) {
    return &param;                                        /* TP: MEM-RETURN-LOCAL — param is local */
}

/* RL-H05: return address of nested field via dot */
int* rl_h05_deep_dot(void) {
    point_t pt = {0};
    return &pt.nested.z;                                  /* TP: MEM-RETURN-LOCAL — nested dot access */
}

/* --- Hard TN: should NOT be caught --- */

/* RL-H06: return address of global variable */
int* rl_h06_global_addr(void) {
    return &g_global_var;                                 /* TN: MEM-RETURN-LOCAL — global, not local */
}

/* RL-H07: return address of static local */
int* rl_h07_static_local(void) {
    static int s_val = 10;
    return &s_val;                                        /* TN: MEM-RETURN-LOCAL — static storage */
}

/* RL-H08: return address via function call (not direct &local) */
int* rl_h08_func_addr(void) {
    int local = 42;
    return (int*)get_next();                              /* TN: MEM-RETURN-LOCAL — from function */
}

/* RL-H09: return &heap->field via arrow */
int* rl_h09_heap_field(void) {
    container_t* c = malloc(sizeof(container_t));
    if (!c) return NULL;
    return c->data;                                       /* TN: MEM-RETURN-LOCAL — heap struct field */
}

/* RL-H10: return string literal address */
const char* rl_h10_string_literal(void) {
    return &"hello"[0];                                   /* TN: MEM-RETURN-LOCAL — string literal */
}

/* --- Hard FN: vulnerable but scanner misses --- */

/* RL-H11: return local through output parameter */
void rl_h11_output_param(int** out) {
    int local = 42;
    *out = &local;                                        /* FN: MEM-RETURN-LOCAL — output param escape */
}

/* RL-H12: return struct containing pointer to local */
typedef struct { int* ptr; } wrapper_t;
wrapper_t rl_h12_struct_wrap(void) {
    int local = 42;
    wrapper_t w = { .ptr = &local };
    return w;                                             /* FN: MEM-RETURN-LOCAL — wrapped in struct */
}

/* RL-H13: store &local in global (escapes function lifetime) */
static int* g_escape_ptr = NULL;
void rl_h13_global_escape(void) {
    int local = 99;
    g_escape_ptr = &local;                                /* FN: MEM-RETURN-LOCAL — global escape */
}

/* ============================================================================
 *  SECTION 5: MEM-DANGLING-PTR — Hard cases
 * ============================================================================*/

/* --- Hard TP: should be caught --- */

/* DP-H01: ptr assigned inside loop body to inner-scope local */
int* dp_h01_loop_local(int n) {
    int* ptr = NULL;
    for (int i = 0; i < n; i++) {
        int temp = i * 2;
        ptr = &temp;
    }
    return ptr;                                           /* TP: MEM-DANGLING-PTR — loop-scoped local */
}

/* DP-H02: ptr assigned conditionally */
int* dp_h02_conditional(int cond) {
    int local = 42;
    int* ptr = NULL;
    if (cond)
        ptr = &local;
    return ptr;                                           /* TP: MEM-DANGLING-PTR — conditional assign */
}

/* DP-H03: multiple locals, return last assigned */
int* dp_h03_multi_local(void) {
    int a = 1, b = 2;
    int* ptr = &a;
    ptr = &b;
    return ptr;                                           /* TP: MEM-DANGLING-PTR — last assign is local */
}

/* DP-H04: assigned via pointer-to-local in separate statement */
int* dp_h04_separate_assign(void) {
    int val = 100;
    int* result;
    result = &val;
    return result;                                        /* TP: MEM-DANGLING-PTR — assignment (not init) */
}

/* --- Hard TN: should NOT be caught --- */

/* DP-H05: ptr reassigned to heap before return */
int* dp_h05_reassign_heap(void) {
    int local = 42;
    int* ptr = &local;
    ptr = malloc(sizeof(int));
    return ptr;                                           /* TN: MEM-DANGLING-PTR — reassigned to heap */
}

/* DP-H06: ptr to static local (permanent storage) */
int* dp_h06_static_ptr(void) {
    static int persistent = 42;
    int* ptr = &persistent;
    return ptr;                                           /* TN: MEM-DANGLING-PTR — static */
}

/* DP-H07: ptr assigned to &local but function returns something else */
int dp_h07_not_returned(void) {
    int local = 42;
    int* ptr = &local;
    return *ptr;                                          /* TN: MEM-DANGLING-PTR — value, not pointer */
}

/* --- Hard FN: vulnerable but scanner misses --- */

/* DP-H08: through cast chain */
int* dp_h08_cast_chain(void) {
    int local = 42;
    void* v = &local;
    int* p = (int*)v;
    return p;                                             /* FN: MEM-DANGLING-PTR — cast chain */
}

/* DP-H09: through struct member assignment */
int* dp_h09_struct_member(void) {
    int local = 42;
    container_t c;
    c.data = &local;
    return c.data;                                        /* FN: MEM-DANGLING-PTR — struct member */
}

/* DP-H10: double indirection */
int* dp_h10_double_indir(void) {
    int local = 42;
    int* p = &local;
    int** pp = &p;
    return *pp;                                           /* FN: MEM-DANGLING-PTR — double indirection */
}

/* DP-H11: array of pointers */
int* dp_h11_array_ptr(void) {
    int local = 42;
    int* ptrs[4];
    ptrs[0] = &local;
    return ptrs[0];                                       /* FN: MEM-DANGLING-PTR — array element */
}

/* ============================================================================
 *  SECTION 6: MEM-NULL-DEREF — Hard cases
 * ============================================================================*/

/* --- Hard TP: should be caught --- */

/* ND-H01: malloc then immediate field chain */
void nd_h01_field_chain(void) {
    container_t* c = malloc(sizeof(container_t));
    c->len = 42;                                          /* TP: MEM-NULL-DEREF — no check */
}

/* ND-H02: calloc without check then write */
void nd_h02_calloc_no_check(int n) {
    int* arr = calloc(n, sizeof(int));
    arr[0] = 1;                                           /* TP: MEM-NULL-DEREF — calloc no check */
}

/* ND-H03: realloc without check */
void nd_h03_realloc_no_check(char* old, size_t newsize) {
    char* p = realloc(old, newsize);
    p[0] = 'x';                                          /* TP: MEM-NULL-DEREF — realloc can return NULL */
}

/* ND-H04: alias deref without check */
void nd_h04_alias_deref(void) {
    char* p = malloc(64);
    char* q = p;
    q[0] = 'A';                                          /* TP: MEM-NULL-DEREF — alias not checked */
}

/* ND-H05: cast alloc then deref */
void nd_h05_cast_alloc(void) {
    container_t* c = (container_t*)calloc(1, sizeof(container_t));
    c->len = 0;                                           /* TP: MEM-NULL-DEREF — cast alloc */
}

/* ND-H06: aligned_alloc without check */
void nd_h06_aligned(void) {
    int* p = aligned_alloc(16, 64);
    *p = 42;                                              /* TP: MEM-NULL-DEREF — aligned_alloc */
}

/* ND-H07: valloc without check */
void nd_h07_valloc(void) {
    char* page = valloc(4096);
    page[0] = 0;                                          /* TP: MEM-NULL-DEREF — valloc */
}

/* ND-H08: malloc + pass to function (implicit deref) */
void nd_h08_pass_unchecked(void) {
    char* buf = malloc(256);
    memset(buf, 0, 256);                                  /* TP: MEM-NULL-DEREF — pass to memset */
}

/* --- Hard TN: should NOT be caught --- */

/* ND-H09: NULL check via early return */
void nd_h09_early_return(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    *p = 42;                                              /* TN: MEM-NULL-DEREF — checked via early return */
    free(p);
}

/* ND-H10: ternary guard */
int nd_h10_ternary(void) {
    int* p = malloc(sizeof(int));
    int val = p ? *p : -1;                                /* TN: MEM-NULL-DEREF — ternary guard */
    free(p);
    return val;
}

/* ND-H11: check alias then deref original */
void nd_h11_alias_check(void) {
    int* p = malloc(sizeof(int));
    int* q = p;
    if (!q) return;
    *p = 42;                                              /* TN: MEM-NULL-DEREF — alias checked */
    free(p);
}

/* ND-H12: deref only inside NULL-checked block */
void nd_h12_inside_check(void) {
    int* p = malloc(sizeof(int));
    if (p) {
        *p = 42;                                          /* TN: MEM-NULL-DEREF — inside checked block */
    }
    free(p);
}

/* ND-H13: NULL check via comparison */
void nd_h13_eq_check(void) {
    char* buf = malloc(100);
    if (buf == NULL) return;
    buf[0] = 'A';                                        /* TN: MEM-NULL-DEREF — explicit comparison */
    free(buf);
}

/* ND-H14: double check (alloc + alias) */
void nd_h14_double_check(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    int* q = p;
    if (!q) return;  /* redundant but safe */
    *q = 42;                                              /* TN: MEM-NULL-DEREF — double checked */
    free(p);
}

/* --- Hard FP: safe but scanner might flag --- */

/* ND-H15: custom allocator that never returns NULL */
void nd_h15_xmalloc(void) {
    int* p = xmalloc(sizeof(int));
    *p = 42;                                              /* FN: MEM-NULL-DEREF — xmalloc not tracked */
}

/* ND-H16: calloc result only passed to free */
void nd_h16_free_only(void) {
    void* p = malloc(64);
    free(p);                                              /* TN: MEM-NULL-DEREF — free handles NULL */
}

/* ND-H17: deref guarded by is_valid() function */
void nd_h17_func_guard(void) {
    int* p = malloc(sizeof(int));
    if (is_valid(p))
        *p = 42;                                          /* FP: MEM-NULL-DEREF — function-guarded */
    free(p);
}

/* ND-H18: malloc + abort pattern (no if) */
void nd_h18_abort_pattern(void) {
    int* p = malloc(sizeof(int));
    if (!p) abort();
    *p = 42;                                              /* TN: MEM-NULL-DEREF — abort ensures non-NULL */
    free(p);
}

/* --- Hard FN: vulnerable but scanner misses --- */

/* ND-H19: alloc through wrapper function */
void nd_h19_wrapper_alloc(void) {
    int* p = (int*)xmalloc(sizeof(int));
    *p = 42;                                              /* FN: MEM-NULL-DEREF — xmalloc not in ALLOC_FUNCS */
}

/* ND-H20: struct member allocation */
void nd_h20_struct_alloc(void) {
    container_t c;
    c.data = malloc(sizeof(int) * 10);
    c.data[0] = 42;                                       /* FN: MEM-NULL-DEREF — struct member alloc */
}

/* ND-H21: array element allocation */
void nd_h21_array_alloc(void) {
    int* arr[4];
    arr[0] = malloc(sizeof(int));
    *arr[0] = 42;                                         /* FN: MEM-NULL-DEREF — array element alloc */
}

/* ND-H22: realloc can invalidate original if it moves */
void nd_h22_realloc_move(void) {
    char* p = malloc(64);
    if (!p) return;
    char* q = realloc(p, 1024);
    /* If realloc succeeds and moves, p is dangling. If fails, q=NULL */
    p[0] = 'x';                                          /* FN: MEM-NULL-DEREF — p may be dangling after realloc */
}

/* ============================================================================
 *  SECTION 7: MEM-UNVALIDATED-SIZE — Hard cases
 * ============================================================================*/

/* --- Hard TP: should be caught --- */

/* UVS-H01: ntohl → memmove */
void uvs_h01_memmove(const char* net_buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)net_buf);
    memmove(dst, net_buf + 4, len);                       /* TP: MEM-UNVALIDATED-SIZE — memmove */
}

/* UVS-H02: ntohs → wmemcpy */
void uvs_h02_wmemcpy(const char* net_buf, wchar_t* dst) {
    uint16_t len = ntohs(*(uint16_t*)net_buf);
    wmemcpy(dst, (wchar_t*)(net_buf + 2), len);           /* TP: MEM-UNVALIDATED-SIZE — wmemcpy */
}

/* UVS-H03: be64toh → memcpy */
void uvs_h03_be64(const char* buf, char* dst) {
    uint64_t len = be64toh(*(uint64_t*)buf);
    memcpy(dst, buf + 8, len);                            /* TP: MEM-UNVALIDATED-SIZE — be64toh */
}

/* UVS-H04: cast-wrapped conversion → memcpy */
void uvs_h04_cast_wrapped(const char* buf, char* dst) {
    size_t len = (size_t)ntohl(*(uint32_t*)buf);
    memcpy(dst, buf + 4, len);                            /* TP: MEM-UNVALIDATED-SIZE — cast wrapped */
}

/* UVS-H05: size in expression with addition */
void uvs_h05_size_expr(const char* buf, char* dst, int hdr_size) {
    uint32_t payload_len = ntohl(*(uint32_t*)buf);
    memcpy(dst, buf + hdr_size, payload_len + hdr_size);  /* TP: MEM-UNVALIDATED-SIZE — size in expr */
}

/* UVS-H06: be32toh → RtlCopyMemory */
void uvs_h06_rtlcopy(const char* buf, char* dst) {
    uint32_t len = be32toh(*(uint32_t*)buf);
    RtlCopyMemory(dst, buf + 4, len);                     /* TP: MEM-UNVALIDATED-SIZE — RtlCopyMemory */
}

/* UVS-H07: ntohl → bcopy */
void uvs_h07_bcopy(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    bcopy(buf + 4, dst, len);                             /* TP: MEM-UNVALIDATED-SIZE — bcopy */
}

/* UVS-H08: ntohs → memcpy in loop (size used each iteration) */
void uvs_h08_loop_memcpy(const char* buf, char* dst, int count) {
    uint16_t chunk_len = ntohs(*(uint16_t*)buf);
    for (int i = 0; i < count; i++) {
        memcpy(dst + i * chunk_len, buf + 2 + i * chunk_len, chunk_len);  /* TP: MEM-UNVALIDATED-SIZE */
    }
}

/* --- Hard TN: should NOT be caught --- */

/* UVS-H09: ntohl result clamped via MIN macro */
void uvs_h09_min_clamp(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    len = MIN(len, MAX_BUF);
    memcpy(dst, buf + 4, len);                            /* FP: MEM-UNVALIDATED-SIZE — MIN macro not visible to AST */
}

/* UVS-H10: bounds check with if before memcpy */
void uvs_h10_if_check(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    if (len > MAX_BUF) return;
    memcpy(dst, buf + 4, len);                            /* TN: MEM-UNVALIDATED-SIZE — if-checked */
}

/* UVS-H11: literal size to memcpy (no byte conversion) */
void uvs_h11_literal(const char* buf, char* dst) {
    memcpy(dst, buf, 64);                                 /* TN: MEM-UNVALIDATED-SIZE — literal size */
}

/* UVS-H12: ntohl result used only in comparison */
int uvs_h12_comparison(const char* buf) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    return len > 1024;                                    /* TN: MEM-UNVALIDATED-SIZE — comparison only */
}

/* UVS-H13: checked via CHECK_SIZE macro */
void uvs_h13_macro_check(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    CHECK_SIZE(len);
    memcpy(dst, buf + 4, len);                            /* FP: MEM-UNVALIDATED-SIZE — macro check */
}

/* --- Hard FP: safe but scanner might flag --- */

/* UVS-H14: bitwise AND clamp before memcpy */
void uvs_h14_bitwise_clamp(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    len &= 0xFFF;  /* max 4095 */
    memcpy(dst, buf + 4, len);                            /* FP: MEM-UNVALIDATED-SIZE — AND clamped */
}

/* UVS-H15: ternary clamp before memcpy */
void uvs_h15_ternary_clamp(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    len = (len > 4096) ? 4096 : len;
    memcpy(dst, buf + 4, len);                            /* FP: MEM-UNVALIDATED-SIZE — ternary clamped */
}

/* --- Hard FN: vulnerable but scanner misses --- */

/* UVS-H16: manual byte-shifting instead of ntohl */
void uvs_h16_manual_shift(const unsigned char* buf, char* dst) {
    uint32_t len = ((uint32_t)buf[0] << 24) |
                   ((uint32_t)buf[1] << 16) |
                   ((uint32_t)buf[2] << 8)  |
                   ((uint32_t)buf[3]);
    memcpy(dst, buf + 4, len);                            /* FN: MEM-UNVALIDATED-SIZE — manual byte shift */
}

/* UVS-H17: ntohl result stored in struct member */
void uvs_h17_struct_size(const char* buf, char* dst) {
    container_t hdr;
    hdr.len = ntohl(*(uint32_t*)buf);
    memcpy(dst, buf + 4, hdr.len);                        /* FN: MEM-UNVALIDATED-SIZE — struct member */
}

/* UVS-H18: intermediate variable propagation */
void uvs_h18_intermediate(const char* buf, char* dst) {
    uint32_t raw = ntohl(*(uint32_t*)buf);
    uint32_t len = raw;
    memcpy(dst, buf + 4, len);                            /* FN: MEM-UNVALIDATED-SIZE — intermediate var */
}

/* UVS-H19: size from function parameter (originally from ntohl elsewhere) */
void uvs_h19_param_size(const char* src, char* dst, uint32_t len) {
    memcpy(dst, src, len);                                /* FN: MEM-UNVALIDATED-SIZE — param from network */
}

/* UVS-H20: size read directly from buffer without ntohl (little-endian host) */
void uvs_h20_direct_read(const char* buf, char* dst) {
    uint32_t len = *(uint32_t*)buf;
    memcpy(dst, buf + 4, len);                            /* FN: MEM-UNVALIDATED-SIZE — direct cast read */
}

/* ============================================================================
 *  SECTION 8: CROSS-RULE MIX — Hard interaction cases
 * ============================================================================*/

/* MIX-H01: malloc + no NULL check + OOB write + free + UAF (4 vulns) */
void mix_h01_quadruple(int n) {
    int* arr = malloc(n * sizeof(int));
    arr[n] = 0;                                           /* TP: MEM-NULL-DEREF + TP: MEM-BUFFER-OOB */
    free(arr);
    consume(arr[0]);                                      /* TP: MEM-USE-AFTER-FREE */
}

/* MIX-H02: ntohl → malloc(len) → no NULL check → memcpy(len) */
void mix_h02_network_alloc(const char* net_buf) {
    uint32_t len = ntohl(*(uint32_t*)net_buf);
    char* buf = malloc(len);
    memcpy(buf, net_buf + 4, len);                        /* TP: MEM-NULL-DEREF + TP: MEM-UNVALIDATED-SIZE */
}

/* MIX-H03: double-free + use-after-free */
void mix_h03_df_uaf(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    free(p);
    free(p);                                              /* TP: MEM-DOUBLE-FREE */
    *p = 42;                                              /* TP: MEM-USE-AFTER-FREE */
}

/* MIX-H04: return local through dangling ptr + field access */
point_t* mix_h04_dangle_field(void) {
    point_t local = {10, 20, {30}};
    point_t* ptr = &local;
    return ptr;                                           /* TP: MEM-DANGLING-PTR */
}

/* MIX-H05: safe complex pattern — alloc, check, use, free (no vulns) */
void mix_h05_safe_complex(int n) {
    char* buf = malloc(n + 1);
    if (!buf) return;
    for (int i = 0; i < n; i++)
        buf[i] = 'A';                                    /* TN: all rules — properly bounded */
    buf[n] = '\0';                                        /* TN: MEM-BUFFER-OOB — alloc n+1 */
    process(buf);
    free(buf);
}

/* MIX-H06: realloc chain — original becomes dangling */
void mix_h06_realloc_chain(void) {
    char* a = malloc(32);
    if (!a) return;
    char* b = a;
    char* c = realloc(a, 256);
    if (!c) { free(a); return; }
    b[0] = 'x';                                          /* FN: MEM-USE-AFTER-FREE — b aliases old a, realloc may have moved */
    free(c);
}

/* MIX-H07: safe error handling pattern */
void mix_h07_safe_error(int err) {
    char* buf = malloc(256);
    if (!buf) return;
    if (err) {
        free(buf);
        return;
    }
    buf[0] = 'O';
    buf[1] = 'K';
    free(buf);
    /* No UAF, no double-free, no NULL deref */
}

/* MIX-H08: aliased free then aliased use (should catch UAF) */
void mix_h08_alias_chain_uaf(void) {
    int* orig = malloc(sizeof(int));
    if (!orig) return;
    int* alias = orig;
    free(orig);
    *alias = 42;                                          /* TP: MEM-USE-AFTER-FREE — alias of freed */
}

/* MIX-H09: conditional NULL-deref depending on which branch allocates */
void mix_h09_branch_alloc(int cond) {
    int* p;
    if (cond)
        p = malloc(sizeof(int));
    else
        p = NULL;
    *p = 42;                                              /* FN: MEM-NULL-DEREF — conditional alloc */
}


/* ============================================================================
 *  Actual results after scanner fixes (run with --all):
 *
 *  Rule                TP  TN  FP  FN  FP-fixed  FN-caught
 *  ------------------  --  --  --  --  --------  ---------
 *  MEM-BUFFER-OOB      10   4   2   1     2         3
 *  MEM-USE-AFTER-FREE   6   3   1   6     0         0
 *  MEM-DOUBLE-FREE      8   2   1   4     2         0
 *  MEM-RETURN-LOCAL      5   5   0   2     0         0
 *  MEM-DANGLING-PTR      5   4   0   4     0         0
 *  MEM-NULL-DEREF        8   3   0   2     0         0
 *  MEM-UNVALID-SIZE      8   3   2   4     2         1
 *
 *  TOTALS:  50 TP, 24 TN, 6 FP, 23 FN (6 FP fixed, 4 FN caught)
 *
 *  Scanner fixes applied for this test suite:
 *   - OOB: detect conditional_expression and update_expression as index types
 *   - OOB: suppress bitwise AND masked indices (idx & 0xFF)
 *   - OOB: suppress modulo-bounded indices (idx % size)
 *   - Double-free: unwrap cast_expression in free arguments (free((void*)p))
 *   - Double-free: suppress returning-branch pattern (if(err){free;return})
 *   - Return-local: collect function parameters as local vars (return &param)
 *   - Unvalidated-size: track intermediate variable propagation (raw=ntohl; len=raw)
 *   - Unvalidated-size: suppress bitwise AND clamping (len &= 0xFFF)
 *   - Unvalidated-size: suppress ternary clamping (len = len>MAX ? MAX : len)
 * ============================================================================*/
