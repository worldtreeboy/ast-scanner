/*
 * mem_safety_extreme_test.c — Extreme difficulty test cases for memory safety rules
 *
 * Every test exploits a SPECIFIC scanner implementation detail:
 * cast chains hiding pointer_expression, array decay without &,
 * loop iterator arithmetic, struct member aliases, dangling ptr via
 * cast_expression, returning branch nesting, deep alias chains,
 * reassignment edge cases, compound literals, and more.
 *
 * Annotation format (inline only):
 *   TP: RULE-ID -- description
 *   TN: RULE-ID -- description
 *   FP: RULE-ID -- description
 *   FN: RULE-ID -- description
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

/* Forward declarations */
extern void process(void*);
extern void consume(int);
extern int get_index(void);
extern int get_condition(void);
extern void* get_ptr(void);
extern void log_msg(const char*);
extern int validate(void*);
extern uint32_t ntohl(uint32_t);
extern uint16_t ntohs(uint16_t);
extern uint32_t be32toh(uint32_t);

/* Types */
typedef struct { int* data; char* name; size_t len; } container_t;
typedef struct { int x; int y; } point_t;
typedef struct node { struct node* next; int val; } node_t;
typedef struct { container_t inner; int flags; } nested_t;

/* Globals */
static int g_val = 42;
static int* g_ptr = NULL;

/* Free-like wrappers not in scanner's FREE_LIKE_FUNCS */
static void custom_release(void* p) { free(p); }
static void destroy_node(node_t* n) { free(n); }

/* ============================================================================
 *  SECTION 1: MEM-BUFFER-OOB — Extreme cases
 * ============================================================================*/

/* E-OOB-01: for-loop iterator used with arithmetic offset — i bounded, i+1 not */
void e_oob_01_iter_offset(int* arr, int n) {
    for (int i = 0; i < n; i++)
        arr[i + 1] = 0;                                  /* TP: MEM-BUFFER-OOB — i bounded but i+1 overflows */
}

/* E-OOB-02: index from sizeof applied to pointer (gives pointer size, not array size) */
void e_oob_02_sizeof_ptr(void) {
    int arr[100];
    int idx = sizeof(&arr[0]);   /* 4 or 8, not 400 */
    arr[idx] = 0;                                         /* FP: MEM-BUFFER-OOB — sizeof gives small constant, scanner can't evaluate */
}

/* E-OOB-03: double subscript (matrix pattern) — outer bounded, inner not */
void e_oob_03_double_sub(int** matrix, int rows, int c) {
    for (int r = 0; r < rows; r++)
        matrix[r][c] = 0;                                /* TP: MEM-BUFFER-OOB — inner subscript[c] unbounded */
}

/* E-OOB-04: index from bit-shift (could be very large) */
void e_oob_04_shift_index(int* arr, int shift) {
    arr[1 << shift] = 0;                                 /* TP: MEM-BUFFER-OOB — shift creates huge index */
}

/* E-OOB-05: compound assignment inside do-while with bounds at bottom */
void e_oob_05_dowhile(int* arr, int n) {
    int i = 0;
    do {
        arr[i] = 0;                                       /* FP: MEM-BUFFER-OOB — bounded by condition below */
        i++;
    } while (i < n);
}

/* E-OOB-06: negative constant from macro (preprocessor invisible to tree-sitter) */
#define NEG_OFF (-3)
void e_oob_06_neg_macro(int* arr) {
    arr[NEG_OFF] = 0;                                     /* TP: MEM-BUFFER-OOB — macro name is identifier, flagged */
}

/* E-OOB-07: alloc-bounded with realloc — realloc(p, n+1) then p[n] */
void e_oob_07_realloc_bounded(int n) {
    int* p = malloc(n);
    if (!p) return;
    p = realloc(p, n + 1);
    if (!p) return;
    p[n] = 0;                                             /* TN: MEM-BUFFER-OOB — realloc(n+1) bounds n */
}

/* E-OOB-08: unsigned underflow in index — large positive after subtraction */
void e_oob_08_unsigned_underflow(int* arr, unsigned int len) {
    unsigned int idx = len - 1;  /* wraps if len==0 */
    arr[idx] = 0;                                         /* TP: MEM-BUFFER-OOB — underflow risk */
}

/* E-OOB-09: index from comma expression */
void e_oob_09_comma(int* arr, int a, int b) {
    arr[(a, b)] = 0;                                      /* TP: MEM-BUFFER-OOB — comma returns b, unbounded */
}

/* E-OOB-10: write through pointer arithmetic (not subscript) */
void e_oob_10_ptr_arith(int* arr, int n) {
    *(arr + n) = 0;                                       /* FN: MEM-BUFFER-OOB — ptr arithmetic, not subscript */
}

/* E-OOB-11: nested binary — index is (a + b) * c */
void e_oob_11_nested_binary(int* arr, int a, int b, int c) {
    arr[(a + b) * c] = 0;                                /* TP: MEM-BUFFER-OOB — complex expression */
}

/* E-OOB-12: alloc with nested addition — malloc(n + padding + 1) then arr[n] */
void e_oob_12_nested_alloc(int n) {
    char* buf = malloc(n + 10 + 1);
    if (!buf) return;
    buf[n] = 'x';                                        /* FP: MEM-BUFFER-OOB — alloc n+10+1, nested addition not parsed */
}

/* ============================================================================
 *  SECTION 2: MEM-USE-AFTER-FREE — Extreme cases
 * ============================================================================*/

/* E-UAF-01: free through struct member, use through same member */
void e_uaf_01_struct_member(void) {
    container_t c;
    c.data = malloc(sizeof(int) * 10);
    if (!c.data) return;
    free(c.data);
    c.data[0] = 42;                                       /* FN: MEM-USE-AFTER-FREE — struct member */
}

/* E-UAF-02: 5-hop alias chain — a→b→c→d→e, free(a), use(e) */
void e_uaf_02_deep_chain(void) {
    int* a = malloc(sizeof(int));
    if (!a) return;
    int* b = a;
    int* c = b;
    int* d = c;
    int* e = d;
    free(a);
    *e = 99;                                              /* TP: MEM-USE-AFTER-FREE — 5-hop alias chain */
}

/* E-UAF-03: conditional free without else — falls through to use */
void e_uaf_03_cond_no_else(int err) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    if (err) {
        free(p);
    }
    /* no else — if err was true, p is freed */
    *p = 42;                                              /* TP: MEM-USE-AFTER-FREE — cond free, no else */
}

/* E-UAF-04: free via custom wrapper (not in FREE_LIKE_FUNCS) */
void e_uaf_04_custom_free(void) {
    node_t* n = malloc(sizeof(node_t));
    if (!n) return;
    destroy_node(n);
    n->val = 42;                                          /* FN: MEM-USE-AFTER-FREE — custom free wrapper */
}

/* E-UAF-05: UAF via array element */
void e_uaf_05_array_elem(void) {
    char* bufs[4];
    bufs[0] = malloc(64);
    if (!bufs[0]) return;
    free(bufs[0]);
    bufs[0][0] = 'A';                                    /* FN: MEM-USE-AFTER-FREE — array element */
}

/* E-UAF-06: realloc invalidates alias */
void e_uaf_06_realloc_alias(void) {
    char* p = malloc(64);
    if (!p) return;
    char* alias = p;
    char* q = realloc(p, 4096);
    if (!q) { free(p); return; }
    alias[0] = 'x';                                      /* FN: MEM-USE-AFTER-FREE — alias of pre-realloc ptr */
}

/* E-UAF-07: free in switch-case, use in fall-through */
void e_uaf_07_switch_fall(int x) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    switch (x) {
    case 1:
        free(p);
        /* fall through! */
    case 2:
        *p = 42;                                          /* TP: MEM-USE-AFTER-FREE — switch fallthrough */
        break;
    }
}

/* E-UAF-08: free then use in next iteration of for-loop */
void e_uaf_08_loop_uaf(int n) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    for (int i = 0; i < n; i++) {
        *p = i;                                           /* TP: MEM-USE-AFTER-FREE — freed in prev iteration */
        free(p);
    }
}

/* E-UAF-09: free in nested if, use outside */
void e_uaf_09_nested_if(int a, int b) {
    char* buf = malloc(128);
    if (!buf) return;
    if (a) {
        if (b) {
            free(buf);
        }
    }
    buf[0] = 'x';                                        /* TP: MEM-USE-AFTER-FREE — nested if free */
}

/* E-UAF-10: safe — free in if with return, use after (exclusive) */
void e_uaf_10_safe_return(int err) {
    char* buf = malloc(128);
    if (!buf) return;
    if (err) {
        free(buf);
        return;
    }
    buf[0] = 'A';                                        /* TN: MEM-USE-AFTER-FREE — error path returns */
    free(buf);
}

/* E-UAF-11: safe — reassign in between free and use */
void e_uaf_11_safe_reassign(const char* src) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    p = strdup(src);
    if (p) p[0] = 'x';                                   /* TN: MEM-USE-AFTER-FREE — reassigned */
    free(p);
}

/* E-UAF-12: safe — free in else branch, use in if branch (exclusive) */
void e_uaf_12_safe_exclusive(int flag) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    if (flag) {
        *p = 42;                                          /* TN: MEM-USE-AFTER-FREE — exclusive branches */
    } else {
        free(p);
        p = NULL;
    }
}

/* ============================================================================
 *  SECTION 3: MEM-DOUBLE-FREE — Extreme cases
 * ============================================================================*/

/* E-DF-01: aliased double-free — q=p, free(p), free(q) */
void e_df_01_alias(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    int* q = p;
    free(p);
    free(q);                                              /* FN: MEM-DOUBLE-FREE — aliased double-free */
}

/* E-DF-02: double-free through struct member */
void e_df_02_struct(void) {
    container_t c;
    c.data = malloc(sizeof(int) * 10);
    if (!c.data) return;
    free(c.data);
    free(c.data);                                         /* FN: MEM-DOUBLE-FREE — struct member */
}

/* E-DF-03: double-free via different cast types */
void e_df_03_multi_cast(void) {
    void* base = malloc(128);
    if (!base) return;
    free((char*)base);
    free((int*)base);                                     /* TP: MEM-DOUBLE-FREE — cast doesn't change ptr */
}

/* E-DF-04: free in deeply nested returning block, then free outside */
void e_df_04_deep_return(int a, int b) {
    char* p = malloc(64);
    if (!p) return;
    if (a) {
        if (b) {
            free(p);
            return;
        }
    }
    process(p);
    free(p);                                              /* TN: MEM-DOUBLE-FREE — deep return path */
}

/* E-DF-05: free in loop body (different allocation each time — safe) */
void e_df_05_loop_alloc(int n) {
    for (int i = 0; i < n; i++) {
        char* p = malloc(64);
        if (!p) continue;
        p[0] = (char)i;
        free(p);
    }
    /* No double-free: each p is a new allocation */
}

/* E-DF-06: free(p), p = NULL, free(p) — free(NULL) is safe */
void e_df_06_null_guard(void) {
    int* p = malloc(sizeof(int));
    if (!p) return;
    free(p);
    p = NULL;
    free(p);                                              /* TN: MEM-DOUBLE-FREE — p is NULL */
}

/* E-DF-07: conditional double-free (both branches free, one path executes both) */
void e_df_07_both_branches(int cond) {
    char* p = malloc(64);
    if (!p) return;
    if (cond)
        free(p);
    free(p);                                              /* TP: MEM-DOUBLE-FREE — if cond true, double free */
}

/* E-DF-08: triple free with intervening log calls (no reassignment) */
void e_df_08_triple(void) {
    void* p = malloc(128);
    if (!p) return;
    free(p);
    log_msg("freed once");
    free(p);                                              /* TP: MEM-DOUBLE-FREE — second */
    log_msg("freed twice");
    free(p);                                              /* TP: MEM-DOUBLE-FREE — third */
}

/* ============================================================================
 *  SECTION 4: MEM-RETURN-LOCAL — Extreme cases
 * ============================================================================*/

/* E-RL-01: return local array name (implicit decay, no & operator) */
int* e_rl_01_array_decay(void) {
    int arr[10] = {0};
    return arr;                                           /* FN: MEM-RETURN-LOCAL — array decay, no & */
}

/* E-RL-02: return (void*)&local — cast wrapping address-of */
void* e_rl_02_cast_addr(void) {
    int local = 42;
    return (void*)&local;                                 /* TP: MEM-RETURN-LOCAL — cast wraps & */
}

/* E-RL-03: return address of compound literal */
int* e_rl_03_compound_literal(void) {
    return &(int){42};                                    /* FN: MEM-RETURN-LOCAL — compound literal not declared */
}

/* E-RL-04: return address of local through multiple nested dots */
int* e_rl_04_deep_nested(void) {
    nested_t outer = {0};
    return outer.inner.data;                              /* TN: MEM-RETURN-LOCAL — pointer member, not address */
}

/* E-RL-05: return address of const local */
const int* e_rl_05_const_local(void) {
    const int val = 100;
    return &val;                                          /* TP: MEM-RETURN-LOCAL — const doesn't extend lifetime */
}

/* E-RL-06: return address of parameter array */
int* e_rl_06_param_array(int arr[10]) {
    return &arr[0];                                       /* TN: MEM-RETURN-LOCAL — arr is pointer param (decay) */
}

/* E-RL-07: safe — return address of static local */
int* e_rl_07_static(void) {
    static int persistent = 10;
    return &persistent;                                   /* TN: MEM-RETURN-LOCAL — static storage */
}

/* E-RL-08: safe — address-of local passed as arg to function (return is function's return) */
int* e_rl_08_func_arg(void) {
    int local = 42;
    return (int*)get_ptr();                               /* TN: MEM-RETURN-LOCAL — from function, not &local */
}

/* E-RL-09: return &local inside comma expression */
int* e_rl_09_comma(void) {
    int local = 42;
    return (log_msg("returning"), &local);                /* TP: MEM-RETURN-LOCAL — comma expr found */
}

/* ============================================================================
 *  SECTION 5: MEM-DANGLING-PTR — Extreme cases
 * ============================================================================*/

/* E-DP-01: dangling via cast chain — void* v = (void*)&local; ptr = (int*)v; return ptr */
int* e_dp_01_cast_chain(void) {
    int local = 42;
    void* v = (void*)&local;
    int* ptr = (int*)v;
    return ptr;                                           /* FN: MEM-DANGLING-PTR — cast hides &local */
}

/* E-DP-02: dangling via struct member */
int* e_dp_02_struct_member(void) {
    int local = 42;
    container_t c;
    c.data = &local;
    return c.data;                                        /* FN: MEM-DANGLING-PTR — struct member assignment */
}

/* E-DP-03: dangling ptr — assigned in one if branch, returned unconditionally */
int* e_dp_03_partial_assign(int cond) {
    int local = 42;
    int* ptr = malloc(sizeof(int));
    if (cond)
        ptr = &local;
    return ptr;                                           /* TP: MEM-DANGLING-PTR — conditional local assign */
}

/* E-DP-04: dangling — reassign ptr AFTER &local but to another local */
int* e_dp_04_reassign_local(void) {
    int a = 1, b = 2;
    int* ptr = &a;
    ptr = &b;
    return ptr;                                           /* TP: MEM-DANGLING-PTR — still dangling */
}

/* E-DP-05: safe — reassign ptr to heap before return */
int* e_dp_05_safe_heap(void) {
    int local = 42;
    int* ptr = &local;
    ptr = malloc(sizeof(int));
    if (ptr) *ptr = local;
    return ptr;                                           /* TN: MEM-DANGLING-PTR — reassigned to heap */
}

/* E-DP-06: safe — ptr assigned &local but function returns *ptr (value, not pointer) */
int e_dp_06_value_return(void) {
    int local = 42;
    int* ptr = &local;
    return *ptr;                                          /* TN: MEM-DANGLING-PTR — value, not pointer */
}

/* E-DP-07: safe — ptr not returned (used and discarded) */
void e_dp_07_not_returned(void) {
    int local = 42;
    int* ptr = &local;
    consume(*ptr);
    /* ptr not returned */
}

/* E-DP-08: dangling via ternary assignment */
int* e_dp_08_ternary_assign(int cond) {
    int local = 42;
    int* heap = malloc(sizeof(int));
    int* ptr = cond ? &local : heap;
    return ptr;                                           /* FN: MEM-DANGLING-PTR — ternary hides &local */
}

/* E-DP-09: dangling via array of pointers */
int* e_dp_09_array(void) {
    int local = 42;
    int* ptrs[4] = {NULL};
    ptrs[0] = &local;
    return ptrs[0];                                       /* FN: MEM-DANGLING-PTR — through array */
}

/* ============================================================================
 *  SECTION 6: MEM-NULL-DEREF — Extreme cases
 * ============================================================================*/

/* E-ND-01: malloc → pass to function → function derefs (implicit deref) */
void e_nd_01_pass_to_func(void) {
    char* buf = malloc(256);
    process(buf);                                         /* TP: MEM-NULL-DEREF — pass without check */
}

/* E-ND-02: calloc → field chain without check */
void e_nd_02_calloc_chain(void) {
    container_t* c = calloc(1, sizeof(container_t));
    c->len = c->flags;                                    /* TP: MEM-NULL-DEREF — calloc not checked */
}

/* E-ND-03: realloc can return NULL and FREE the old pointer */
void e_nd_03_realloc_null(void) {
    char* p = malloc(64);
    if (!p) return;
    p = realloc(p, 1024 * 1024);
    /* if realloc fails, p is now NULL AND old allocation is leaked */
    p[0] = 'x';                                          /* TP: MEM-NULL-DEREF — realloc may return NULL */
}

/* E-ND-04: alias through cast, check original, deref cast version */
void e_nd_04_cast_alias(void) {
    void* p = malloc(64);
    if (!p) return;
    char* q = (char*)p;
    q[0] = 'A';                                          /* TN: MEM-NULL-DEREF — p checked, q is alias */
}

/* E-ND-05: NULL check via assert (compile-time removal in release) */
void e_nd_05_assert_check(void) {
    int* p = malloc(sizeof(int));
    assert(p != NULL);
    *p = 42;                                              /* FP: MEM-NULL-DEREF — assert may be compiled out */
    free(p);
}

/* E-ND-06: NULL check via comma + abort */
void e_nd_06_comma_abort(void) {
    int* p = malloc(sizeof(int));
    (void)(p || (abort(), 0));
    *p = 42;                                              /* FP: MEM-NULL-DEREF — or-abort pattern */
    free(p);
}

/* E-ND-07: safe — deref only inside if(p) block */
void e_nd_07_guarded_block(void) {
    int* p = malloc(sizeof(int));
    if (p) {
        *p = 42;                                          /* TN: MEM-NULL-DEREF — inside if(p) */
        free(p);
    }
}

/* E-ND-08: safe — early return on NULL */
void e_nd_08_early_return(void) {
    char* buf = malloc(100);
    if (buf == NULL) return;
    buf[0] = 'A';                                        /* TN: MEM-NULL-DEREF — early return */
    free(buf);
}

/* E-ND-09: safe — ternary guard */
int e_nd_09_ternary_guard(void) {
    int* p = malloc(sizeof(int));
    int val = p ? *p : -1;                                /* TN: MEM-NULL-DEREF — ternary guard */
    free(p);
    return val;
}

/* E-ND-10: struct member allocation — not tracked */
void e_nd_10_struct_alloc(void) {
    container_t c;
    c.data = malloc(sizeof(int) * 10);
    c.data[0] = 42;                                       /* FN: MEM-NULL-DEREF — struct member alloc */
}

/* E-ND-11: array element allocation — not tracked */
void e_nd_11_array_alloc(void) {
    int* ptrs[4];
    ptrs[0] = malloc(sizeof(int));
    *ptrs[0] = 42;                                        /* FN: MEM-NULL-DEREF — array element alloc */
}

/* E-ND-12: malloc result immediately cast and assigned */
void e_nd_12_immediate_cast(void) {
    node_t* n = (node_t*)malloc(sizeof(node_t));
    n->val = 0;                                           /* TP: MEM-NULL-DEREF — cast alloc no check */
}

/* E-ND-13: double alias check — check q (alias of p), deref p */
void e_nd_13_alias_cross_check(void) {
    int* p = malloc(sizeof(int));
    int* q = p;
    if (!q) return;
    *p = 42;                                              /* TN: MEM-NULL-DEREF — alias q checked */
    free(p);
}

/* E-ND-14: safe — only passed to free (free(NULL) is OK) */
void e_nd_14_free_only(void) {
    void* p = malloc(64);
    free(p);                                              /* TN: MEM-NULL-DEREF — free handles NULL */
}

/* E-ND-15: safe — NULL check via goto pattern */
void e_nd_15_goto_check(void) {
    char* buf = malloc(256);
    if (!buf) goto cleanup;
    buf[0] = 'x';                                        /* TN: MEM-NULL-DEREF — goto on NULL */
    free(buf);
    return;
cleanup:
    return;
}

/* E-ND-16: pvalloc without check */
void e_nd_16_pvalloc(void) {
    char* page = pvalloc(4096);
    page[0] = 0;                                          /* TP: MEM-NULL-DEREF — pvalloc can return NULL */
}

/* ============================================================================
 *  SECTION 7: MEM-UNVALIDATED-SIZE — Extreme cases
 * ============================================================================*/

/* E-UVS-01: intermediate variable chain — raw→adj→len→memcpy */
void e_uvs_01_chain(const char* buf, char* dst) {
    uint32_t raw = ntohl(*(uint32_t*)buf);
    uint32_t adj = raw;
    uint32_t len = adj;
    memcpy(dst, buf + 4, len);                            /* TP: MEM-UNVALIDATED-SIZE — 3-hop chain */
}

/* E-UVS-02: ntohl result used in subtraction then memcpy */
void e_uvs_02_sub_expr(const char* buf, char* dst) {
    uint32_t total = ntohl(*(uint32_t*)buf);
    memcpy(dst, buf + 8, total - 4);                      /* TP: MEM-UNVALIDATED-SIZE — subtraction */
}

/* E-UVS-03: size from struct member after byte swap */
void e_uvs_03_struct_field(const char* buf, char* dst) {
    container_t hdr;
    hdr.len = ntohl(*(uint32_t*)buf);
    memcpy(dst, buf + 4, hdr.len);                        /* FN: MEM-UNVALIDATED-SIZE — struct member */
}

/* E-UVS-04: manual byte shifting (no ntohl — not in BYTE_CONVERSION_FUNCS) */
void e_uvs_04_manual_shift(const unsigned char* buf, char* dst) {
    uint32_t len = ((uint32_t)buf[0] << 24) |
                   ((uint32_t)buf[1] << 16) |
                   ((uint32_t)buf[2] << 8)  |
                   ((uint32_t)buf[3]);
    memcpy(dst, buf + 4, len);                            /* FN: MEM-UNVALIDATED-SIZE — manual byte shift */
}

/* E-UVS-05: safe — bounds check via if before memcpy */
void e_uvs_05_if_check(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    if (len > 4096) return;
    memcpy(dst, buf + 4, len);                            /* TN: MEM-UNVALIDATED-SIZE — if checked */
}

/* E-UVS-06: safe — bitwise AND clamp */
void e_uvs_06_and_clamp(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    len &= 0xFFF;
    memcpy(dst, buf + 4, len);                            /* TN: MEM-UNVALIDATED-SIZE — AND clamped */
}

/* E-UVS-07: safe — ternary clamp */
void e_uvs_07_ternary_clamp(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    len = (len > 4096) ? 4096 : len;
    memcpy(dst, buf + 4, len);                            /* TN: MEM-UNVALIDATED-SIZE — ternary clamped */
}

/* E-UVS-08: ntohs → memcpy (16-bit conversion) */
void e_uvs_08_ntohs(const char* buf, char* dst) {
    uint16_t len = ntohs(*(uint16_t*)buf);
    memcpy(dst, buf + 2, len);                            /* TP: MEM-UNVALIDATED-SIZE — ntohs unvalidated */
}

/* E-UVS-09: be32toh → memmove */
void e_uvs_09_be32(const char* buf, char* dst) {
    uint32_t len = be32toh(*(uint32_t*)buf);
    memmove(dst, buf + 4, len);                           /* TP: MEM-UNVALIDATED-SIZE — be32toh→memmove */
}

/* E-UVS-10: direct cast read from buffer (no ntohl — not tracked) */
void e_uvs_10_direct_read(const char* buf, char* dst) {
    uint32_t len = *(uint32_t*)buf;
    memcpy(dst, buf + 4, len);                            /* FN: MEM-UNVALIDATED-SIZE — direct read */
}

/* E-UVS-11: ntohl result reassigned via compound assignment (len += header) */
void e_uvs_11_compound_assign(const char* buf, char* dst) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    len += 8;  /* add header size */
    memcpy(dst, buf, len);                                /* TP: MEM-UNVALIDATED-SIZE — compound assign keeps taint */
}

/* E-UVS-12: size from function parameter (originally from ntohl elsewhere) */
void e_uvs_12_param_size(const char* src, char* dst, uint32_t network_len) {
    memcpy(dst, src, network_len);                        /* FN: MEM-UNVALIDATED-SIZE — param, no conversion */
}

/* E-UVS-13: safe — literal size */
void e_uvs_13_literal(const char* buf, char* dst) {
    memcpy(dst, buf, 64);                                 /* TN: MEM-UNVALIDATED-SIZE — literal size */
}

/* E-UVS-14: safe — comparison only, no memcpy */
int e_uvs_14_comparison(const char* buf) {
    uint32_t len = ntohl(*(uint32_t*)buf);
    return len > 1024;                                    /* TN: MEM-UNVALIDATED-SIZE — comparison only */
}

/* ============================================================================
 *  SECTION 8: CROSS-RULE MIX — Extreme interaction cases
 * ============================================================================*/

/* E-MIX-01: malloc → no check → free → use → free (NULL-deref + UAF + double-free) */
void e_mix_01_triple_vuln(void) {
    int* p = malloc(sizeof(int));
    *p = 42;                                              /* TP: MEM-NULL-DEREF — no check */
    free(p);
    consume(*p);                                          /* TP: MEM-USE-AFTER-FREE — freed */
    free(p);                                              /* TP: MEM-DOUBLE-FREE — double free */
}

/* E-MIX-02: ntohl → malloc(len) → no check → memcpy (unvalidated + null-deref) */
void e_mix_02_network_chain(const char* net_buf) {
    uint32_t len = ntohl(*(uint32_t*)net_buf);
    char* buf = malloc(len);
    memcpy(buf, net_buf + 4, len);                        /* TP: MEM-NULL-DEREF */ /* TP: MEM-UNVALIDATED-SIZE */
}

/* E-MIX-03: return &local through dangling ptr chain */
point_t* e_mix_03_dangle_chain(void) {
    point_t local = {10, 20};
    point_t* ptr = &local;
    return ptr;                                           /* TP: MEM-DANGLING-PTR — stack local */
}

/* E-MIX-04: safe complex pattern — alloc, check, bounded loop, free */
void e_mix_04_safe_complex(int n) {
    if (n <= 0 || n > 1024) return;
    int* arr = malloc(n * sizeof(int));
    if (!arr) return;
    for (int i = 0; i < n; i++)
        arr[i] = i;                                       /* TN: all rules — properly bounded */
    free(arr);
}

/* E-MIX-05: safe — error goto pattern with cleanup */
int e_mix_05_goto_cleanup(int size) {
    char* a = malloc(size);
    char* b = malloc(size);
    if (!a || !b) goto fail;
    a[0] = 'x';
    b[0] = 'y';
    free(a);
    free(b);
    return 0;
fail:
    free(a);                                              /* FP: MEM-DOUBLE-FREE — goto separates paths */
    free(b);                                              /* FP: MEM-DOUBLE-FREE — goto separates paths */
    return -1;
}

/* E-MIX-06: double-free + UAF in same function */
void e_mix_06_df_uaf(void) {
    char* p = malloc(64);
    if (!p) return;
    free(p);
    p[0] = 'x';                                          /* TP: MEM-USE-AFTER-FREE */
    free(p);                                              /* TP: MEM-DOUBLE-FREE */
}

/* E-MIX-07: realloc pattern — check new, alias old still valid on failure */
void e_mix_07_realloc_safe(void) {
    char* p = malloc(64);
    if (!p) return;
    char* q = realloc(p, 256);
    if (q) {
        p = q;
    }
    /* p still valid (either original or new) */
    p[0] = 'A';                                          /* TN: all rules — safe realloc pattern */
    free(p);
}

/* E-MIX-08: conditional allocation with only one branch returning pointer */
int* e_mix_08_cond_alloc(int use_heap) {
    if (use_heap) {
        int* p = malloc(sizeof(int));
        if (p) *p = 42;
        return p;                                         /* TN: all rules — heap allocated */
    }
    int local = 42;
    return &local;                                        /* TP: MEM-RETURN-LOCAL — stack in else */
}


/* ============================================================================
 *  Results summary (after scanner fixes)
 *
 *  Rule                  TP  TN  FP  FN
 *  --------------------  --  --  --  --
 *  MEM-BUFFER-OOB         7   1   3   1
 *  MEM-USE-AFTER-FREE     7   3   0   4
 *  MEM-DOUBLE-FREE        6   2   2   2
 *  MEM-RETURN-LOCAL        4   4   0   2
 *  MEM-DANGLING-PTR        3   2   0   4
 *  MEM-NULL-DEREF          7   7   2   2
 *  MEM-UNVALIDATED-SIZE    6   5   0   4
 *  --------------------  --  --  --  --
 *  TOTAL                  40  24   7  19
 * ============================================================================*/
