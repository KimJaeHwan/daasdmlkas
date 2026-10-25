/* Raw register use in naked cases is fixture code, not an engine ABI model. */
typedef unsigned long long word;
__attribute__((noinline)) word case_summary_branch(word initial, word yes, word count, word selector, word no) {
    volatile word cell = initial, remaining = count;
    while (remaining != 0) {
        if (selector != 0) cell += yes;
        else cell += no;
        --remaining;
    }
    return cell;
}
__attribute__((noinline)) word case_summary_feedback(word initial, word yes, word count) {
    volatile word cell = initial, remaining = count;
    while (remaining != 0) {
        if ((remaining & 1) != 0) cell += yes;
        else cell += 3;
        --remaining;
    }
    return cell;
}
#define HEAD "mov %rdi,%rax\n1: cmp $0,%rdx\nje 2f\n"
#define TAIL "sub $1,%rdx\njmp 1b\n2: ret\n"
__attribute__((naked,noinline)) word case_strided_store(word base, word value, word count) {
    __asm__(HEAD "mov %rsi,(%rax)\nadd $8,%rax\n" TAIL);
}
__attribute__((naked,noinline)) word case_strided_after(word base, word value, word count) {
    __asm__(HEAD "add $8,%rax\nmov %rsi,(%rax)\n" TAIL);
}
__attribute__((naked,noinline)) word case_strided_load(word base, word value, word count) {
    __asm__(HEAD "mov (%rax),%rcx\nmov %rsi,(%rax)\nadd $8,%rax\n" TAIL);
}
__attribute__((naked,noinline)) word case_strided_mutable(word base, word value, word count) {
    __asm__(HEAD "mov %rdx,(%rax)\nadd $8,%rax\n" TAIL);
}
__attribute__((naked,noinline)) word case_strided_overlap(word base, word value, word count) {
    __asm__(HEAD "mov %rsi,(%rax)\nadd $4,%rax\n" TAIL);
}
