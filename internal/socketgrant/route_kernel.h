#ifndef FG_ROUTE_KERNEL_H
#define FG_ROUTE_KERNEL_H
#include <stdint.h>
struct fg_route_gate;
struct fg_route_gate *fg_route_open(const char *,const char *,int *);
int fg_route_add(struct fg_route_gate *,uint32_t);
int fg_route_retire(struct fg_route_gate *,uint32_t);
int fg_route_epoch(struct fg_route_gate *,uint64_t);
int fg_route_put(struct fg_route_gate *,void *,void *);
int fg_route_delete(struct fg_route_gate *,void *);
int fg_route_stats(struct fg_route_gate *,void *,void *);
int fg_route_totals(struct fg_route_gate *,void *);
int fg_route_detach(struct fg_route_gate *);
int fg_route_close(struct fg_route_gate *);
int fg_route_release_removed(struct fg_route_gate *);
#endif
