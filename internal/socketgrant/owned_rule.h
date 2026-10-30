#ifndef FLOWGATE_OWNED_RULE_H
#define FLOWGATE_OWNED_RULE_H
#include <stdint.h>
#include <libnftnl/rule.h>
struct fg_owned_rule {
 char table[64], chain[64];
 unsigned char tag[128];
 uint32_t tag_len;
 uint64_t handle;
};
int fg_rule_identity(struct fg_owned_rule *,const char *,const char *);
int fg_rule_insert(struct fg_owned_rule *,struct nftnl_rule *);
int fg_rule_remove(struct fg_owned_rule *);
int fg_rule_absent(struct fg_owned_rule *);
#endif
