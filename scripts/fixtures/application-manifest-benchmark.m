/* Read-only timing wrappers, compiled only by the unprivileged benchmark. */
#include "../../native/macos-pf-routing/gui-launch.m"
int envara_benchmark_tree(const char *bundle) { char physical[65],content[65]; return tree_walk(bundle,0,1,physical,content,NULL); }
int envara_benchmark_identity(const char *bundle) { char identity[65]; return tree_walk(bundle,0,0,NULL,NULL,identity); }
int envara_benchmark_signature(const char *bundle) { struct envara_gui_manifest out={0}; return sign_info(bundle,&out); }
