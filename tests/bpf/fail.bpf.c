/* Minimal BPF program that fails verification.
 * Missing NULL check on bpf_map_lookup_elem return value.
 */
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

struct {
    __uint(type, 1);        /* BPF_MAP_TYPE_HASH */
    __uint(max_entries, 1);
    unsigned int *key;
    unsigned long long *value;
} stats SEC(".maps");

SEC("socket")
int fail_prog(void *ctx) {
    unsigned int key = 0;
    unsigned long long *val = bpf_map_lookup_elem(&stats, &key);
    /* BUG: no NULL check — verifier rejects this */
    (*val)++;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
