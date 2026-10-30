#include <stdint.h>
struct fg_gate;
struct fg_gate *fg_open(int *);
int fg_epoch(struct fg_gate *, uint64_t);
int fg_put(struct fg_gate *, void *, void *);
int fg_delete(struct fg_gate *, void *);
int fg_stats(struct fg_gate *, void *, void *);
int fg_totals(struct fg_gate *, void *);
int fg_close(struct fg_gate *);
