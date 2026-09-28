/* Compile the exact paper corpus unchanged, with only its entry-point renamed. */
#define write_u16_le paper_write_u16_le
#define write_u32_le paper_write_u32_le
#define read_u16_le paper_read_u16_le
#define read_u32_le paper_read_u32_le
#define main paper_equivalence_main
#pragma GCC diagnostic push
/* The unchanged host corpus uses %x for uint32_t; STM32's typedef is long. */
#pragma GCC diagnostic ignored "-Wformat"
#include "../Provenance/reference_corpus/test_equivalence.c"
#pragma GCC diagnostic pop

int paper_equivalence_board_run(void)
{
    int result = paper_equivalence_main();
    /* newlib-nano on the F767 does not format the corpus's %llu correctly. */
    printf("[PAPER CORPUS] comparisons=%lu failures=%d\n",
           (unsigned long)comparisons, failures);
    return result;
}
