/* BPF program for round-trip datasec testing.
 * Variables span .rodata, .data, and .bss to exercise parse_rodata
 * on real bpftool JSON output from all three datasec types.
 *
 * .rodata (const volatile — frozen map, verifier constant-folds):
 *   int, unsigned long long, _Bool, int[4], char[8]
 *
 * .data (non-const, non-zero initializer — mutable map):
 *   int, unsigned long long
 *
 * .bss (non-const, zero-initialized — mutable map):
 *   int, unsigned long long
 *
 * Defaults (mode=0): verifier prunes the if-body, minimal insns.
 * Override mode=1 via -G: verifier explores all branches, more insns.
 */
#define SEC(name) __attribute__((section(name), used))

/* .rodata */
const volatile int mode = 0;
const volatile unsigned long long big_val = 5000000001ULL; /* > 2^32, not a boundary */
const volatile _Bool flag = 0;
const volatile int arr[4] = {17, 42, 99, 253};
const volatile char name[8] = "hello";

/* .data — volatile prevents compile-time constant folding of initializers */
volatile int data_counter = 137;
volatile int data_limit = 8642;

/* .bss — zero-initialized */
volatile int bss_state;
volatile int bss_counter;

SEC("socket")
int roundtrip_prog(void *ctx) {
    int ret = 0;

    /* Read .rodata */
    ret += (int)(big_val & 0xFF);
    if (flag) ret += 1;
    ret += arr[0] + arr[1] + arr[2] + arr[3];
    ret += name[0];

    /* Read .data */
    ret += data_counter;
    ret += data_limit;

    /* Read .bss */
    ret += bss_state;
    ret += bss_counter;

    /* mode=1 triggers branch exploration for delta testing */
    if (mode == 1) {
        if (arr[0] > 0) ret += 16;
        if (arr[1] > 0) ret += 32;
        if (arr[2] > 0) ret += 64;
        if (arr[3] > 0) ret += 128;
        if (big_val > 50) ret += 256;
        if (flag) ret += 512;
        if (name[0] > 'a') ret += 1024;
        if (name[1] > 'a') ret += 2048;
    }

    return ret;
}

char LICENSE[] SEC("license") = "GPL";
