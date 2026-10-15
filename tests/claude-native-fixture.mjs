import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile } from 'node:fs/promises';

// Small real native executable: records argv, and mimics the installer's
// atomic native-entry replacement. It never contacts a service or reads auth.
export async function compileClaudeFixture(filename, version = '2.1.296') {
  const source = `${filename}.c`;
  await writeFile(source, `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void text(const char *s) { putchar('"'); if(s) for(const unsigned char *p=(const unsigned char*)s; *p; p++) { if(*p=='"'||*p=='\\\\') putchar('\\\\'); if(*p<32) printf("\\\\u%04x",*p); else putchar(*p); } putchar('"'); }
int main(int argc,char **argv) {
  for(int i=1;i<argc;i++) if(!strcmp(argv[i],"update")) {
    const char *next=getenv("ENVARA_TEST_NEXT_VERSION"), *home=getenv("HOME");
    if(!next||!home) return 42;
    char staging[8192],entry[8192];
    snprintf(staging,sizeof(staging),"%s/.local/bin/.fixture-next-%ld",home,(long)getpid());
    snprintf(entry,sizeof(entry),"%s/.local/bin/claude",home);
    if(symlink(next,staging)||rename(staging,entry)) return 43;
  }
  printf("{\\"version\\":");text("${version}");printf(",\\"args\\":[");
  for(int i=1;i<argc;i++){if(i>1)putchar(',');text(argv[i]);}
  printf("],\\"home\\":");text(getenv("HOME"));printf(",\\"config\\":");text(getenv("CLAUDE_CONFIG_DIR"));printf(",\\"path\\":");text(getenv("PATH"));puts("}");
  return 0;
}
`, { mode: 0o600 });
  await promisify(execFile)('/usr/bin/cc', [source, '-o', filename], { timeout: 30000 });
}
