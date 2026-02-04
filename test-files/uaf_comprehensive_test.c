/**
 * uaf_comprehensive_test.c — Comprehensive Use-After-Free test suite
 *
 * Tests ONLY the MEM-USE-AFTER-FREE rule for:
 *   TP  = True Positive   — vulnerable code, scanner SHOULD flag it
 *   TN  = True Negative   — safe code, scanner should NOT flag it
 *   FP  = False Positive  — safe code, scanner INCORRECTLY flags (known)
 *   FN  = False Negative  — vulnerable code, scanner MISSES (known limitation)
 *
 * Every test function is named: uaf_<tp|tn|fp|fn>_<description>_<N>
 * Every flaggable line annotated with expected outcome.
 *
 * NOTE: TN cases avoid guard patterns like if(!p){free(x);return;} on
 *       OTHER variables that would create collateral FPs.
 *
 * Run:
 *   python3 c_cpp_treesitter_scanner.py test-files/uaf_comprehensive_test.c --all
 *   python3 c_cpp_treesitter_scanner.py test-files/uaf_comprehensive_test.c --all --jsonl 2>/dev/null
 *
 * === EXPECTED SUMMARY ===
 *   TP (True Positive)  = 31  (scanner correctly flags vulnerable code)
 *   TN (True Negative)  = 20  (scanner correctly stays silent on safe code)
 *   FP (False Positive)  = 10  (scanner flags safe code — known limitation)
 *   FN (False Negative)  = 13  (scanner misses vulnerable code — known limitation)
 *
 *   Total MEM-USE-AFTER-FREE findings expected: 41 (= 31 TP + 10 FP)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Stubs */
extern void use_ptr(void*);
extern void use_int(int);
extern int  get_cond(void);
extern void log_msg(const char*);
extern void process_data(const char*, size_t);
extern int  validate(void*);
extern void* custom_alloc(size_t);
extern void  custom_free(void*);

typedef struct { int x; int y; } point_t;
typedef struct { char* name; int id; } record_t;
typedef struct node { int val; struct node* next; } node_t;


/* ============================================================================
 *  TRUE POSITIVES — Scanner SHOULD flag these (31 cases)
 *
 *  Categories:
 *    basic     — straightforward free-then-use
 *    access    — various dereference patterns after free
 *    alias     — alias-tracking scenarios
 *    multi/gap — multiple uses after free / code between free and use
 *    evasive   — harder-to-detect but still same-scope patterns
 * ============================================================================*/

/* TP-1: Classic free then dereference read */
void uaf_tp_basic_1(void) {
    int* p = (int*)malloc(sizeof(int));
    if (!p) return;
    *p = 42;
    free(p);
    printf("%d\n", *p);                         /* TP: MEM-USE-AFTER-FREE */
}

/* TP-2: Free then write through pointer */
void uaf_tp_basic_2(void) {
    char* buf = (char*)malloc(64);
    if (!buf) return;
    buf[0] = 'A';
    free(buf);
    buf[0] = 'H';                               /* TP: MEM-USE-AFTER-FREE */
}

/* TP-3: Free then pass to printf */
void uaf_tp_basic_3(void) {
    char* msg = (char*)malloc(128);
    if (!msg) return;
    snprintf(msg, 128, "test");
    free(msg);
    printf("%s\n", msg);                         /* TP: MEM-USE-AFTER-FREE */
}

/* TP-4: Free then return the freed pointer */
char* uaf_tp_basic_4(void) {
    char* p = (char*)malloc(32);
    if (!p) return NULL;
    p[0] = 'x';
    free(p);
    return p;                                    /* TP: MEM-USE-AFTER-FREE */
}

/* TP-5: Free then pass to function call */
void uaf_tp_basic_5(void) {
    char* data = (char*)malloc(256);
    if (!data) return;
    memset(data, 0, 256);
    free(data);
    use_ptr(data);                               /* TP: MEM-USE-AFTER-FREE */
}

/* TP-6: Struct member read after free (arrow operator) */
void uaf_tp_access_1(void) {
    point_t* pt = (point_t*)malloc(sizeof(point_t));
    if (!pt) return;
    pt->x = 1;
    free(pt);
    int val = pt->x;                             /* TP: MEM-USE-AFTER-FREE */
    (void)val;
}

/* TP-7: Struct member write after free */
void uaf_tp_access_2(void) {
    point_t* pt = (point_t*)malloc(sizeof(point_t));
    if (!pt) return;
    free(pt);
    pt->y = 99;                                  /* TP: MEM-USE-AFTER-FREE */
}

/* TP-8: Array subscript write after free */
void uaf_tp_access_3(void) {
    int* arr = (int*)malloc(10 * sizeof(int));
    if (!arr) return;
    arr[0] = 1;
    free(arr);
    arr[5] = 42;                                 /* TP: MEM-USE-AFTER-FREE */
}

/* TP-9: Dereference in comparison after free */
void uaf_tp_access_4(void) {
    int* p = (int*)malloc(sizeof(int));
    if (!p) return;
    *p = 10;
    free(p);
    if (*p == 10) {                              /* TP: MEM-USE-AFTER-FREE */
        printf("stale\n");
    }
}

/* TP-10: strlen on freed string */
void uaf_tp_access_5(void) {
    char* s = (char*)malloc(100);
    if (!s) return;
    s[0] = 'a'; s[1] = '\0';
    free(s);
    size_t len = strlen(s);                      /* TP: MEM-USE-AFTER-FREE */
    (void)len;
}

/* TP-11: memcpy with freed source */
void uaf_tp_access_6(void) {
    char* src = (char*)malloc(64);
    if (!src) return;
    memset(src, 'A', 64);
    free(src);
    char dst[64];
    memcpy(dst, src, 64);                        /* TP: MEM-USE-AFTER-FREE */
}

/* TP-12: Freed pointer in arithmetic expression */
void uaf_tp_access_7(void) {
    int* arr = (int*)malloc(10 * sizeof(int));
    if (!arr) return;
    arr[0] = 5; arr[1] = 10;
    free(arr);
    int sum = arr[0] + arr[1];                   /* TP: MEM-USE-AFTER-FREE */
    (void)sum;
}

/* TP-13: Freed pointer compared with another (still a use) */
void uaf_tp_access_8(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    char* sentinel = p;
    free(p);
    if (sentinel == p) {                         /* TP: MEM-USE-AFTER-FREE (p used in ==) */
        printf("match\n");
    }
}

/* TP-14: Simple alias via init: q = p; free(p); use q */
void uaf_tp_alias_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    char* q = p;
    free(p);
    printf("%s\n", q);                           /* TP: MEM-USE-AFTER-FREE via alias q */
}

/* TP-15: Alias via assignment (not declaration init) */
void uaf_tp_alias_2(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    char* q;
    q = p;
    free(p);
    printf("%c\n", q[0]);                        /* TP: MEM-USE-AFTER-FREE via alias q */
}

/* TP-16: Alias for struct pointer, member access via alias */
void uaf_tp_alias_3(void) {
    point_t* orig = (point_t*)malloc(sizeof(point_t));
    if (!orig) return;
    point_t* alias = orig;
    orig->x = 1;
    free(orig);
    alias->y = 2;                                /* TP: MEM-USE-AFTER-FREE via alias */
}

/* TP-17: Alias passed to function after original freed */
void uaf_tp_alias_4(void) {
    char* buf = (char*)malloc(256);
    if (!buf) return;
    char* ref = buf;
    free(buf);
    process_data(ref, 256);                      /* TP: MEM-USE-AFTER-FREE via alias ref */
}

/* TP-18: Alias used in loop body after original freed */
void uaf_tp_alias_5(void) {
    int* data = (int*)malloc(100 * sizeof(int));
    if (!data) return;
    int* cursor = data;
    free(data);
    for (int i = 0; i < 10; i++) {
        use_int(cursor[i]);                      /* TP: MEM-USE-AFTER-FREE via alias cursor */
    }
}

/* TP-19: Multiple uses after free (first is flagged) */
void uaf_tp_multi_1(void) {
    int* p = (int*)malloc(sizeof(int) * 10);
    if (!p) return;
    free(p);
    p[0] = 1;                                   /* TP: MEM-USE-AFTER-FREE (first use) */
    p[1] = 2;
    printf("%d\n", p[0]);
}

/* TP-20: Lots of unrelated code between free and use */
void uaf_tp_gap_1(void) {
    char* p = (char*)malloc(100);
    if (!p) return;
    free(p);
    int x = 42;
    printf("x = %d\n", x);
    log_msg("doing stuff");
    int y = x * 2;
    (void)y;
    printf("%s\n", p);                           /* TP: MEM-USE-AFTER-FREE — far from free */
}

/* TP-21: Free one ptr, work with others, then use the freed one */
void uaf_tp_gap_2(void) {
    char* a = (char*)malloc(32);
    char* b = (char*)malloc(32);
    if (!a) return;
    if (!b) { free(a); return; }
    free(a);
    printf("b = %p\n", (void*)b);
    use_ptr(a);                                  /* TP: MEM-USE-AFTER-FREE — a freed above */
    free(b);
}

/* TP-22: Free, then use in loop body */
void uaf_tp_loop_1(void) {
    int* arr = (int*)malloc(10 * sizeof(int));
    if (!arr) return;
    free(arr);
    for (int i = 0; i < 10; i++) {
        arr[i] = i;                              /* TP: MEM-USE-AFTER-FREE — loop body */
    }
}

/* TP-23: Free then use in ternary expression */
void uaf_tp_evasive_1(void) {
    int* p = (int*)malloc(sizeof(int));
    if (!p) return;
    *p = 5;
    free(p);
    int val = (*p > 3) ? 1 : 0;                 /* TP: MEM-USE-AFTER-FREE — ternary */
    (void)val;
}

/* TP-24: Free then variable subscript base */
void uaf_tp_evasive_2(int idx) {
    char* buf = (char*)malloc(256);
    if (!buf) return;
    free(buf);
    char c = buf[idx];                           /* TP: MEM-USE-AFTER-FREE */
    (void)c;
}

/* TP-25: sizeof(p) after free — scanner treats as use (technically not a
   runtime dereference but scanner cannot distinguish) */
void uaf_tp_evasive_3(void) {
    point_t* p = (point_t*)malloc(sizeof(point_t));
    if (!p) return;
    free(p);
    printf("size = %zu\n", sizeof(p));           /* TP: MEM-USE-AFTER-FREE — sizeof(p) references p */
}

/* TP-26: Freed pointer stored in array initializer */
void uaf_tp_evasive_4(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    free(p);
    char* ptrs[] = { p, NULL };                  /* TP: MEM-USE-AFTER-FREE — p in initializer */
    (void)ptrs;
}

/* TP-27: Free then use in write() system call */
void uaf_tp_evasive_5(void) {
    char* buf = (char*)malloc(128);
    if (!buf) return;
    memset(buf, 'X', 128);
    free(buf);
    write(1, buf, 128);                          /* TP: MEM-USE-AFTER-FREE — write syscall */
}

/* TP-28: Free then cast-and-assign (pointer still used as RHS) */
void uaf_tp_evasive_6(void) {
    void* p = malloc(64);
    if (!p) return;
    free(p);
    char* s = (char*)p;                          /* TP: MEM-USE-AFTER-FREE — cast after free */
    (void)s;
}

/* TP-29: Linked-list alias: tmp = head; free(head); use tmp */
void uaf_tp_evasive_7(void) {
    node_t* head = (node_t*)malloc(sizeof(node_t));
    if (!head) return;
    head->val = 1;
    head->next = NULL;
    node_t* tmp = head;
    free(head);
    printf("val = %d\n", tmp->val);              /* TP: MEM-USE-AFTER-FREE via alias tmp */
}

/* TP-30: Conditional free, unconditional use (sometimes freed) */
void uaf_tp_evasive_8(int flag) {
    char* p = (char*)malloc(64);
    if (!p) return;
    if (flag) {
        free(p);
    }
    printf("%s\n", p);                           /* TP: MEM-USE-AFTER-FREE — may be freed */
}

/* TP-31: Global pointer freed then used in same function */
static char* g_buf = NULL;
void uaf_tp_global_1(void) {
    g_buf = (char*)malloc(128);
    if (!g_buf) return;
    free(g_buf);
    printf("%s\n", g_buf);                       /* TP: MEM-USE-AFTER-FREE — global, same scope */
}


/* ============================================================================
 *  TRUE NEGATIVES — Scanner should NOT flag these (20 cases)
 *
 *  Categories:
 *    cleanup   — proper free-at-end patterns
 *    reassign  — pointer reassigned between free and use
 *    diffvar   — different variables
 *    valcopy   — value copied before free, copy used
 *    scope     — different functions / loop scopes
 *    cond      — conditional patterns that are safe
 * ============================================================================*/

/* TN-1: Free at end, no use after */
void uaf_tn_cleanup_1(void) {
    char* buf = (char*)malloc(256);
    if (!buf) return;
    memset(buf, 0, 256);
    printf("buf = %p\n", (void*)buf);
    free(buf);
    /* nothing after free — TN */
}

/* TN-2: Free + return value copy (not the pointer) */
int uaf_tn_cleanup_2(void) {
    int* p = (int*)malloc(sizeof(int));
    if (!p) return -1;
    *p = 42;
    int val = *p;
    free(p);
    return val;                                  /* TN: val is a value copy */
}

/* TN-3: Free + set to NULL + guarded use */
void uaf_tn_cleanup_3(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    free(p);
    p = NULL;
    if (p) {                                     /* TN: p is NULL */
        printf("%s\n", p);
    }
}

/* TN-4: Single free, nothing after */
void uaf_tn_cleanup_4(void) {
    int* nums = (int*)malloc(10 * sizeof(int));
    if (!nums) return;
    nums[0] = 1;
    nums[9] = 2;
    free(nums);
}

/* TN-5: Free then reassign (malloc) then use */
void uaf_tn_reassign_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    free(p);
    p = (char*)malloc(128);
    if (!p) return;
    printf("%s\n", p);                           /* TN: p reassigned after free */
    free(p);
}

/* TN-6: Free then reassign to static buffer */
void uaf_tn_reassign_2(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    free(p);
    static char fallback[64] = "default";
    p = fallback;
    printf("%s\n", p);                           /* TN: p points to static */
}

/* TN-7: Free then reassign via function return */
void uaf_tn_reassign_3(void) {
    void* p = malloc(64);
    if (!p) return;
    free(p);
    p = custom_alloc(128);
    if (!p) return;
    use_ptr(p);                                  /* TN: p reassigned */
    custom_free(p);
}

/* TN-8: Free then reassign to NULL then to new alloc */
void uaf_tn_reassign_4(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    free(p);
    p = NULL;
    p = (char*)malloc(256);
    if (!p) return;
    printf("%s\n", p);                           /* TN: p doubly reassigned */
    free(p);
}

/* TN-9: Free one variable, use a completely different one */
void uaf_tn_diffvar_1(void) {
    char* a = (char*)malloc(32);
    if (!a) return;
    char* b = (char*)malloc(32);
    if (!b) { free(a); return; }
    free(a);
    printf("%s\n", b);                           /* TN: b is alive, only a freed */
    free(b);
}

/* TN-10: Similar variable names but distinct */
void uaf_tn_diffvar_2(void) {
    int* ptr1 = (int*)malloc(sizeof(int));
    if (!ptr1) return;
    int* ptr2 = (int*)malloc(sizeof(int));
    if (!ptr2) { free(ptr1); return; }
    free(ptr1);
    *ptr2 = 42;                                  /* TN: ptr2 != ptr1 */
    printf("%d\n", *ptr2);
    free(ptr2);
}

/* TN-11: Free one, use another — separate allocs with separate null checks */
void uaf_tn_diffvar_3(void) {
    char* first = (char*)malloc(32);
    if (!first) return;
    char* second = (char*)malloc(32);
    if (!second) { free(first); return; }
    free(first);
    printf("%s\n", second);                      /* TN: second is alive */
    free(second);
}

/* TN-12: Copy scalar value before free, use copy */
void uaf_tn_valcopy_1(void) {
    int* p = (int*)malloc(sizeof(int));
    if (!p) return;
    *p = 42;
    int saved = *p;
    free(p);
    printf("%d\n", saved);                       /* TN: saved is a value copy */
}

/* TN-13: Copy struct by value before free */
void uaf_tn_valcopy_2(void) {
    point_t* pt = (point_t*)malloc(sizeof(point_t));
    if (!pt) return;
    pt->x = 10;
    pt->y = 20;
    point_t copy = *pt;
    free(pt);
    printf("x=%d y=%d\n", copy.x, copy.y);      /* TN: copy is value, not pointer */
}

/* TN-14: Copy string content before free */
void uaf_tn_valcopy_3(void) {
    char* src = (char*)malloc(64);
    if (!src) return;
    snprintf(src, 64, "hello");
    char local[64];
    snprintf(local, sizeof(local), "%s", src);
    free(src);
    printf("%s\n", local);                       /* TN: local is a copy */
}

/* TN-15: Same variable name, completely different function */
void uaf_tn_scope_helper(void) {
    char* data = (char*)malloc(64);
    if (!data) return;
    free(data);
}
void uaf_tn_scope_1(void) {
    char* data = (char*)malloc(64);
    if (!data) return;
    printf("%s\n", data);                        /* TN: different function's data */
    free(data);
}

/* TN-16: Free and re-allocate in each loop iteration */
void uaf_tn_scope_2(void) {
    for (int i = 0; i < 5; i++) {
        char* tmp = (char*)malloc(32);
        if (!tmp) continue;
        tmp[0] = 'A' + i;
        free(tmp);
    }
}

/* TN-17: Free at very end, conditional use before */
void uaf_tn_cond_1(int cond) {
    char* p = (char*)malloc(64);
    if (!p) return;
    if (cond) {
        use_ptr(p);
    }
    free(p);                                     /* TN: free is always last */
}

/* TN-18: Only use after free is another free (double-free, not UAF) */
void uaf_tn_onlyfree_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    free(p);
    free(p);                                     /* TN for UAF: handled as double-free */
}

/* TN-19: Nested scope, inner alloc freed, outer still alive */
void uaf_tn_nested_1(void) {
    char* outer = (char*)malloc(64);
    if (!outer) return;
    use_ptr(outer);
    char* inner = (char*)malloc(32);
    if (inner) {
        use_ptr(inner);
        free(inner);
    }
    printf("%s\n", outer);                       /* TN: outer never freed until below */
    free(outer);
}

/* TN-20: No use of freed variable at all (void statement after) */
void uaf_tn_nouse_1(void) {
    int* p = (int*)malloc(sizeof(int));
    if (!p) return;
    *p = 1;
    free(p);
    (void)0;                                     /* TN: no reference to p */
}


/* ============================================================================
 *  FALSE POSITIVES — Scanner flags but code is actually safe (10 cases)
 *
 *  All caused by lack of control-flow / branch analysis.
 * ============================================================================*/

/* FP-1: Free in if-branch, use in else-branch (exclusive paths) */
void uaf_fp_branch_1(int cond) {
    char* p = (char*)malloc(64);
    if (!p) return;
    if (cond) {
        free(p);
    } else {
        printf("%s\n", p);                       /* FP: MEM-USE-AFTER-FREE — branches exclusive */
        free(p);
    }
}

/* FP-2: Free in error-return branch, use on normal path */
void uaf_fp_errret_1(int err) {
    char* p = (char*)malloc(64);
    if (!p) return;
    if (err) {
        free(p);
        return;
    }
    printf("%s\n", p);                           /* FP: MEM-USE-AFTER-FREE — free path returns */
    free(p);
}

/* FP-3: Free guarded by flag, use guarded by opposite flag */
void uaf_fp_guard_1(int done) {
    char* p = (char*)malloc(64);
    if (!p) return;
    if (done) {
        free(p);
    }
    if (!done) {
        printf("%s\n", p);                       /* FP: MEM-USE-AFTER-FREE — done/!done exclusive */
        free(p);
    }
}

/* FP-4: Free in error path with goto, use only on normal path */
void uaf_fp_goto_1(int fail) {
    char* p = (char*)malloc(64);
    if (!p) return;
    if (fail) {
        free(p);
        goto done;
    }
    printf("%s\n", p);                           /* FP: MEM-USE-AFTER-FREE — goto skips this */
    free(p);
done:
    return;
}

/* FP-5: Free inside one switch case, use in another (exclusive) */
void uaf_fp_switch_1(int action) {
    char* p = (char*)malloc(64);
    if (!p) return;
    switch (action) {
    case 0:
        free(p);
        break;
    case 1:
        printf("%s\n", p);                       /* FP: MEM-USE-AFTER-FREE — cases exclusive */
        free(p);
        break;
    default:
        free(p);
        break;
    }
}

/* FP-6: Free in loop with break+flag, guarded use after loop */
void uaf_fp_loop_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    int ok = 1;
    for (int i = 0; i < 10; i++) {
        if (!validate(p)) {
            free(p);
            ok = 0;
            break;
        }
    }
    if (ok) {
        printf("%s\n", p);                       /* FP: MEM-USE-AFTER-FREE — free only if !ok */
        free(p);
    }
}

/* FP-7: sizeof(ptr) after free — sizeof is compile-time, no runtime deref */
void uaf_fp_sizeof_1(void) {
    int* p = (int*)malloc(sizeof(int));
    if (!p) return;
    free(p);
    size_t sz = sizeof(p);                       /* FP: MEM-USE-AFTER-FREE — sizeof is not a real use */
    (void)sz;
}

/* FP-8: Variable shadowing — inner scope declares same name */
void uaf_fp_shadow_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    free(p);
    {
        char* p = (char*)malloc(128);            /* FP: MEM-USE-AFTER-FREE — inner p shadows outer */
        if (!p) return;
        printf("%s\n", p);
        free(p);
    }
}

/* FP-9: Free in null-check guard for second alloc */
void uaf_fp_guard_alloc_1(void) {
    char* a = (char*)malloc(32);
    if (!a) return;
    char* b = (char*)malloc(32);
    if (!b) { free(a); return; }
    use_ptr(a);                                  /* FP: MEM-USE-AFTER-FREE — guard frees a but returns */
    free(a);
    free(b);
}

/* FP-10: Multiple error-return paths each free then return */
int uaf_fp_multi_guard_1(void) {
    char* buf = (char*)malloc(256);
    if (!buf) return -1;
    if (get_cond()) {
        free(buf);
        return 1;
    }
    if (get_cond()) {
        free(buf);
        return 2;
    }
    use_ptr(buf);                                /* FP: MEM-USE-AFTER-FREE — all free paths return */
    free(buf);
    return 0;
}


/* ============================================================================
 *  FALSE NEGATIVES — Scanner MISSES these (13 cases)
 *
 *  Categories:
 *    crossfunc — free in another function
 *    wrapper   — free via wrapper / function pointer / macro
 *    expr_free — free argument is not a simple identifier
 *    realloc   — implicit free via realloc
 *    cast      — alias via void* cast
 *    chain     — multi-hop alias chains (> 1 level)
 *    struct    — pointer stored in struct field
 *    dblptr    — free via double pointer dereference
 * ============================================================================*/

/* FN-1: Free in callee, use in caller */
static char* g_ptr;
void fn_helper_free(void) { free(g_ptr); }
void uaf_fn_crossfunc_1(void) {
    g_ptr = (char*)malloc(64);
    if (!g_ptr) return;
    fn_helper_free();
    printf("%s\n", g_ptr);                       /* FN: freed in another function */
}

/* FN-2: Free via custom wrapper function */
void my_free(void* p) { free(p); }
void uaf_fn_wrapper_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    my_free(p);
    printf("%s\n", p);                           /* FN: freed via custom wrapper */
}

/* FN-3: Free via function pointer */
typedef void (*dealloc_fn)(void*);
void uaf_fn_funcptr_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    dealloc_fn fn = (dealloc_fn)free;
    fn(p);
    printf("%s\n", p);                           /* FN: freed via function pointer */
}

/* FN-4: free(struct->field) — argument is member expression, not identifier */
void uaf_fn_member_free_1(void) {
    record_t r;
    r.name = (char*)malloc(64);
    if (!r.name) return;
    r.id = 1;
    free(r.name);
    printf("name: %s\n", r.name);               /* FN: free arg is r.name */
}

/* FN-5: free(arr[i]) — argument is subscript, not identifier */
void uaf_fn_array_free_1(void) {
    char* a = (char*)malloc(32);
    char* b = (char*)malloc(32);
    char* c = (char*)malloc(32);
    if (!a || !b || !c) return;
    char* arr[3] = { a, b, c };
    free(arr[0]);
    printf("%s\n", arr[0]);                      /* FN: free arg is arr[0] */
    free(arr[1]);
    free(arr[2]);
}

/* FN-6: realloc can move memory; old alias becomes stale */
void uaf_fn_realloc_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    char* old = p;
    p = (char*)realloc(p, 4096);
    if (!p) return;                              /* leaks old, but no explicit free */
    printf("%s\n", old);                         /* FN: old may be dangling if realloc moved */
    free(p);
}

/* FN-7: Free through void* cast — different name */
void uaf_fn_cast_1(void) {
    int* p = (int*)malloc(sizeof(int) * 10);
    if (!p) return;
    void* vp = p;
    free(vp);
    printf("%d\n", p[0]);                        /* FN: freed as vp, p is same address */
}

/* FN-8: Multi-hop alias chain: a -> b -> c (scanner tracks 1 level) */
void uaf_fn_chain_1(void) {
    char* a = (char*)malloc(64);
    if (!a) return;
    char* b = a;
    char* c = b;
    free(a);
    printf("%s\n", c);                           /* FN: c -> b -> a */
}

/* FN-9: Alias created from another alias after free */
void uaf_fn_chain_2(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    char* saved = p;
    free(p);
    char* q = saved;
    printf("%s\n", q);                           /* FN: q = saved = p */
}

/* FN-10: Pointer stored in struct field, freed via original name */
void uaf_fn_struct_1(void) {
    char* data = (char*)malloc(64);
    if (!data) return;
    record_t rec;
    rec.name = data;
    free(data);
    printf("name: %s\n", rec.name);             /* FN: rec.name == data */
}

/* FN-11: Pointer stored in another struct field */
void uaf_fn_struct_2(void) {
    char* val = (char*)malloc(64);
    if (!val) return;
    record_t holder;
    holder.name = val;
    free(val);
    printf("%s\n", holder.name);                 /* FN: holder.name == val */
}

/* FN-12: Free hidden behind macro */
#define UNSAFE_RELEASE(ptr) free(ptr)
void uaf_fn_macro_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    UNSAFE_RELEASE(p);
    printf("%s\n", p);                           /* FN: UNSAFE_RELEASE expands to free */
}

/* FN-13: free(*pp) — argument is pointer dereference */
void uaf_fn_doubleptr_1(void) {
    char* p = (char*)malloc(64);
    if (!p) return;
    char** pp = &p;
    free(*pp);
    printf("%s\n", *pp);                         /* FN: free arg is *pp, not identifier */
}
