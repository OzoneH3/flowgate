// Namespace-only regression: include implementation to exercise the generation
// race boundary deterministically without a production fault-injection switch.
#include "../../internal/socketgrant/owned_rule.c"
#include <stdio.h>
#include <unistd.h>

static void require(int condition,const char *name) {
 if(!condition){fprintf(stderr,"FAIL %s errno=%d\n",name,errno);exit(1);}
}
static void insert_empty(struct fg_owned_rule *owned) {
 struct nftnl_rule *rule=target(owned);
 require(rule!=NULL,"allocate");
 int rc=fg_rule_insert(owned,rule);
 nftnl_rule_free(rule);
 if(rc)fprintf(stderr,"insert rc=%d\n",rc);
 require(rc==0 && owned->handle!=0,"insert acknowledged and found");
}
int main(void) {
 require(getpid()==1,"private PID namespace init");
 struct fg_owned_rule a,b;
 require(fg_rule_identity(&a,"fg_owned_probe","gate")==0,"identity a");
 require(fg_rule_identity(&b,"fg_owned_probe","gate")==0,"identity b");
 insert_empty(&a);
 uint64_t handle=0;
 require(lookup(&a,&handle)==0 && handle==a.handle,"exact lookup");
 require(system("nft list ruleset >/dev/null")==0,"nft userdata formatting");
 puts("PASS insert acknowledged, tag confirmed, nft formatting valid");
 // Lost reply recovery retains the unpredictable tag, never guesses a handle.
 a.handle=0;
 require(fg_rule_remove(&a)==0,"remove without remembered handle");
 require(lookup(&a,&handle)==0 && handle==0,"removed after missing handle");
 puts("PASS tag recovery without remembered reply handle");
 insert_empty(&a);
 uint32_t generation=0;
 require(current_generation(&generation)==0,"read generation");
 require(lookup(&a,&handle)==0 && handle!=0,"lookup before race");
 insert_empty(&b); // An independent writer wins after our ownership lookup.
 require(remove_generation(&a,generation,handle)==-EAGAIN,"stale generation refused");
 require(lookup(&a,&handle)==0 && handle!=0,"target survives conflict");
 require(fg_rule_remove(&a)==0,"retry with fresh generation");
 require(lookup(&b,&handle)==0 && handle==b.handle,"foreign rule preserved");
 puts("PASS generation race refused; fresh retry preserves foreign rule");
 require(fg_rule_remove(&a)==0,"absent cleanup idempotent");
 require(fg_rule_remove(&b)==0,"cleanup second owner");
 puts("PASS exact cleanup and repeated cleanup");
 return 0;
}
