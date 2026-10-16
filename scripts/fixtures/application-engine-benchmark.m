/* Inspects application bytes/signatures; never executes or copies an app. */
#include "../../native/macos-pf-routing/notion-launch.m"
#include <time.h>
extern int envara_benchmark_tree(const char *);
extern int envara_benchmark_signature(const char *);
static double milliseconds(void) { struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t)) return 0; return t.tv_sec*1000.0+t.tv_nsec/1e6; }
int main(int argc,char **argv) { @autoreleasepool {
 if(argc!=2 || !getuid() || getuid()!=geteuid()) return 2;
 NSMutableArray *results=[NSMutableArray array]; struct envara_gui_manifest manifest={0}; int rc;
#define TIMED(label,expression) do { double start=milliseconds(); errno=0; rc=(expression); int error=rc?errno:0; \
 [results addObject:@{@"operation":label,@"elapsedMs":@(milliseconds()-start),@"success":rc==0?@YES:@NO,@"errno":@(error)}]; } while(0)
 TIMED(@"treeHashOneScan",envara_benchmark_tree(argv[1]));
 TIMED(@"strictNestedSignature",envara_benchmark_signature(argv[1]));
 TIMED(@"manifestInspect",envara_gui_manifest_inspect(argv[1],0,&manifest));
 if(rc) return 3;
 TIMED(@"manifestUnchanged",envara_gui_manifest_unchanged(&manifest));
 TIMED(@"engineMetadata",engine_metadata(&manifest,NULL)==ENVARA_NOTION_ENGINE_NONE?-1:0);
 TIMED(@"engineFull",envara_notion_supported(&manifest));
 /* Same native checks as the original implementation: direct core calls
  * outside a validation scope cannot reuse any signature witness. */
 TIMED(@"fourRepeatedBoundariesUnscoped",({int failed=0;for(unsigned i=0;i<4&&!failed;i++) failed=envara_gui_manifest_unchanged(&manifest)||notion_engine_in_scope(&manifest,NULL);failed?-1:0;}));
 if(!envara_gui_validation_scope_begin()) return 5;
 TIMED(@"fourRepeatedBoundariesScoped",({int failed=0;for(unsigned i=0;i<4&&!failed;i++) failed=envara_gui_manifest_unchanged(&manifest)||envara_notion_supported(&manifest);failed?-1:0;}));
 envara_gui_validation_scope_end();
#undef TIMED
 NSData *data=[NSJSONSerialization dataWithJSONObject:@{@"schema":@"envara.application-engine-cost/v1",@"readOnly":@YES,
 @"applicationExecuted":@NO,@"systemMutated":@NO,@"measurements":results} options:0 error:NULL];
 return !data || fwrite(data.bytes,1,data.length,stdout)!=data.length || putchar('\n')==EOF ? 4:0;
} }
