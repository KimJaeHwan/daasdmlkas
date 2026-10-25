/* Same original graph: a proven MBA island feeds later arithmetic. */
typedef unsigned long long word;
__attribute__((noinline)) word case_consumer_chain(word x, word y) {
    word middle = (x ^ y) + ((x & y) << 1);
    return (middle ^ 0x91) + 9;
}
