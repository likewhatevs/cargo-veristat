/* Minimal BPF program that passes verification.
 * Has rodata variables to test veristat -G global overrides.
 *
 * With defaults (mode=0): verifier prunes the if-body, minimal insns.
 * With mode=1, threshold=500: verifier explores all branches, more insns.
 */
#define SEC(name) __attribute__((section(name), used))

const volatile int mode = 0;
const volatile int threshold = 0;

SEC("socket")
int pass_prog(void *ctx) {
    int ret = 0;
    if (mode == 1) {
        if (threshold > 10) ret += 1;
        if (threshold > 20) ret += 2;
        if (threshold > 30) ret += 4;
        if (threshold > 40) ret += 8;
        if (threshold > 50) ret += 16;
        if (threshold > 60) ret += 32;
        if (threshold > 70) ret += 64;
        if (threshold > 80) ret += 128;
    }
    return ret;
}

char LICENSE[] SEC("license") = "GPL";
