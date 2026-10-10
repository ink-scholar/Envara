import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, realpathSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Real stopped children belong only to this unprivileged fixture. Wrappers
// fault the parent's post-stop identity/cleanup calls; the child's self-read
// and all descriptor closure remain real. No root, PF, app or network access.
test('launcher clears rejected identity only after exact terminal reap and retains unknown custody',
  { skip: process.platform !== 'darwin' }, () => {
    assert.notEqual(process.getuid(), 0);
    assert.equal(process.getuid(), process.geteuid());
    const launcher = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../native/macos-pf-routing/launcher.c');
    const sourceHash = createHash('sha256').update(readFileSync(launcher)).digest('hex');
    const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-launcher-owned-fixture-')));
    try {
      const source = path.join(temporary, 'fixture.c'), executable = path.join(temporary, 'fixture');
      writeFileSync(source, `
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <fcntl.h>
#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>

static pid_t owner_pid, fork_pid, unrelated_pid;
static const char *mode;
static int parent_identity_faulted, cleanup_waits, terminal_reaped, interrupted, wrong_reaped;
static int fixture_proc_pidinfo(int pid, int flavor, uint64_t argument, void *buffer, int size) {
    int result = proc_pidinfo(pid, flavor, argument, buffer, size);
    if (getpid() == owner_pid && fork_pid == pid && flavor == PROC_PIDTBSDINFO && strcmp(mode, "control")) {
        parent_identity_faulted = 1;
        if (!strcmp(mode, "read-failure-cleared") || !strcmp(mode, "read-failure-retained")) { errno = EACCES; return -1; }
        if (result == sizeof(struct proc_bsdinfo)) ((struct proc_bsdinfo *)buffer)->pbi_svuid++;
    }
    return result;
}
static pid_t fixture_waitpid(pid_t pid, int *status, int options) {
    if (getpid() == owner_pid && options == WNOHANG && pid == fork_pid && parent_identity_faulted) {
        cleanup_waits++;
        if (!strcmp(mode, "cleanup-eintr-cleared") && !interrupted++) { errno = EINTR; return -1; }
        if (!strcmp(mode, "cleanup-echild-retained") || !strcmp(mode, "read-failure-retained") || !strcmp(mode, "kill-esrch-retained")) { errno = ECHILD; return -1; }
        if (!strcmp(mode, "cleanup-timeout-retained")) return 0;
        if (!strcmp(mode, "nonterminal-retained")) { *status = (SIGSTOP << 8) | 0x7f; return pid; }
        if (!strcmp(mode, "wrong-child-retained")) {
            pid_t result = waitpid(unrelated_pid, status, 0);
            if (result == unrelated_pid && (WIFEXITED(*status) || WIFSIGNALED(*status))) wrong_reaped = 1;
            return result;
        }
        pid_t result = waitpid(pid, status, options);
        if (result == pid && (WIFEXITED(*status) || WIFSIGNALED(*status))) terminal_reaped = 1;
        return result;
    }
    pid_t result = waitpid(pid, status, options);
    if (getpid() == owner_pid && result == pid && (options & WUNTRACED) && WIFSTOPPED(*status)) fork_pid = pid;
    return result;
}
static int fixture_kill(pid_t pid, int signal) {
    if (getpid() == owner_pid && pid == fork_pid && signal == SIGKILL && !strcmp(mode, "kill-esrch-retained")) { errno = ESRCH; return -1; }
    return kill(pid, signal);
}
static int fixture_clock_gettime(clockid_t clock, struct timespec *out) {
    if (getpid() == owner_pid && parent_identity_faulted && !strcmp(mode, "clock-failure-retained")) { errno = EIO; return -1; }
    return clock_gettime(clock, out);
}
#define proc_pidinfo fixture_proc_pidinfo
#define waitpid fixture_waitpid
#define kill fixture_kill
#define clock_gettime fixture_clock_gettime
#include ${JSON.stringify(launcher)}
#undef proc_pidinfo
#undef waitpid
#undef kill
#undef clock_gettime

static int reap_owned(pid_t pid, int *status) {
    if (pid < 2) return 0;
    pid_t result; do { result = waitpid(pid, status, WNOHANG); } while (result < 0 && errno == EINTR);
    if (result == pid) return WIFEXITED(*status) || WIFSIGNALED(*status);
    if (result != 0) return 0; /* No signal after ECHILD or unknown custody. */
    (void)kill(pid, SIGKILL);
    do { result = waitpid(pid, status, 0); } while (result < 0 && errno == EINTR);
    return result == pid && (WIFEXITED(*status) || WIFSIGNALED(*status));
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "owned-exec")) return 0;
    if (argc != 3 || getuid() == 0 || getuid() != geteuid() || getgid() != getegid()) return 2;
    owner_pid = getpid(); mode = argv[1];
    if (!strcmp(mode, "wrong-child-retained")) {
        unrelated_pid = fork(); if (unrelated_pid < 0) return 3; if (!unrelated_pid) _exit(23);
    }
    char *arguments[] = {argv[0], "owned-exec", NULL};
    char *environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
    struct envara_child child; memset(&child, 0, sizeof(child)); child.error_fd = -1;
    struct timespec first, last; clock_gettime(CLOCK_MONOTONIC, &first);
    int result = envara_spawn_suspended(getuid(), getgid(), argv[2], argv[0], arguments, environment, 1, &child);
    int error = errno; clock_gettime(CLOCK_MONOTONIC, &last);
    long long elapsed = (long long)(last.tv_sec - first.tv_sec) * 1000 + (last.tv_nsec - first.tv_nsec) / 1000000;
    int control = !strcmp(mode, "control"), cleared = strstr(mode, "cleared") != NULL;
    int ok = fork_pid > 1, status = 0, retained_reader = 0, owned_terminal = 0;
    if (control) {
        ok = ok && !result && !parent_identity_faulted && child.identity.pid == fork_pid && child.identity.parent_pid == owner_pid &&
            child.identity.birth_seconds && envara_identity_matches(&child.identity, getuid(), getgid()) && child.error_fd >= 3;
        if (!ok || envara_child_resume(&child)) { ok = 0; owned_terminal = reap_owned(fork_pid, &status); }
        else {
            pid_t done; do { done = waitpid(fork_pid, &status, 0); } while (done < 0 && errno == EINTR);
            owned_terminal = done == fork_pid && WIFEXITED(status) && !WEXITSTATUS(status);
        }
        int exec_error = 0; ok = ok && owned_terminal && read(child.error_fd, &exec_error, sizeof(exec_error)) == 0;
    } else if (cleared) {
        struct envara_identity empty = {0};
        ok = ok && result == -1 && error == EACCES && parent_identity_faulted && terminal_reaped &&
            !memcmp(&child.identity, &empty, sizeof(empty)) && child.error_fd == -1;
        errno = 0; ok = ok && waitpid(fork_pid, &status, WNOHANG) == -1 && errno == ECHILD;
        owned_terminal = terminal_reaped;
        if (!strcmp(mode, "cleanup-eintr-cleared")) ok = ok && interrupted && cleanup_waits >= 2;
    } else {
        retained_reader = child.error_fd >= 3 && fcntl(child.error_fd, F_GETFD) >= 0;
        ok = ok && result == -1 && error == EACCES && parent_identity_faulted && !terminal_reaped &&
            child.identity.pid == fork_pid && child.identity.parent_pid == owner_pid && retained_reader;
        if (!strcmp(mode, "read-failure-retained")) ok = ok && !child.identity.birth_seconds;
        else ok = ok && child.identity.birth_seconds;
        if (!strcmp(mode, "cleanup-timeout-retained")) ok = ok && elapsed >= 1900 && elapsed < 3500 && cleanup_waits > 1;
        if (!strcmp(mode, "clock-failure-retained")) ok = ok && !cleanup_waits && elapsed < 1000;
        if (!strcmp(mode, "wrong-child-retained")) ok = ok && wrong_reaped;
        owned_terminal = reap_owned(fork_pid, &status); ok = ok && owned_terminal;
    }
    if (child.error_fd >= 3) close(child.error_fd);
    if (unrelated_pid > 1 && !wrong_reaped) (void)reap_owned(unrelated_pid, &status);
    if (!owned_terminal) (void)reap_owned(fork_pid, &status);
    printf("{\\"ok\\":%s,\\"mode\\":\\"%s\\",\\"fixtureOnly\\":true,\\"activatesSystem\\":false,\\"ready\\":false,\\"protected\\":false,\\"ownedChildReaped\\":%s,\\"identityCleared\\":%s,\\"retainedReader\\":%s,\\"cleanupWaits\\":%d,\\"elapsedMs\\":%lld}\\n",
        ok ? "true" : "false", mode, owned_terminal ? "true" : "false", cleared ? "true" : "false", retained_reader ? "true" : "false", cleanup_waits, elapsed);
    return ok ? 0 : 1;
}
`, { mode: 0o600 });
      const compiled = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`, source, '-o', executable],
      { encoding: 'utf8', timeout: 60_000, cwd: temporary });
      assert.equal(compiled.error, undefined, compiled.error?.message);
      assert.equal(compiled.signal, null, compiled.stderr);
      assert.equal(compiled.status, 0, compiled.stderr);
      const scenarios = ['control', 'mismatch-cleared', 'read-failure-cleared', 'cleanup-eintr-cleared',
        'cleanup-echild-retained', 'read-failure-retained', 'cleanup-timeout-retained', 'kill-esrch-retained',
        'wrong-child-retained', 'nonterminal-retained', 'clock-failure-retained'];
      for (const scenario of scenarios) {
        const run = spawnSync(executable, [scenario, temporary], { encoding: 'utf8', timeout: 10_000, cwd: temporary });
        assert.equal(run.error, undefined, `${scenario}: ${run.error?.message}`);
        assert.equal(run.signal, null, `${scenario}: ${run.stderr}`);
        assert.equal(run.status, 0, `${scenario}: ${run.stderr}\n${run.stdout}`);
        const report = JSON.parse(run.stdout);
        assert.equal(report.ok, true, scenario);
        assert.equal(report.mode, scenario);
        assert.equal(report.ownedChildReaped, true, `${scenario}: teardown positively reaps the fixture's child`);
        assert.equal(report.identityCleared, scenario.includes('cleared'), scenario);
        assert.equal(report.retainedReader, scenario.includes('retained'), scenario);
        for (const flag of ['activatesSystem', 'ready', 'protected']) assert.equal(report[flag], false, scenario);
      }
      assert.equal(createHash('sha256').update(readFileSync(launcher)).digest('hex'), sourceHash, 'launcher source stayed frozen during fixture execution');
    } finally { rmSync(temporary, { recursive: true, force: true }); }
  });

test('real cold children stalled before SIGSTOP have bounded waits and retain unconfirmed custody',
  { skip: process.platform !== 'darwin' }, () => {
    assert.notEqual(process.getuid(), 0);
    const launcher = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../native/macos-pf-routing/launcher.c');
    const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'envara-cold-stop-deadline-')));
    try {
      const source = path.join(temporary, 'fixture.c'), executable = path.join(temporary, 'fixture');
      writeFileSync(source, `
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <fcntl.h>
#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
static pid_t owner, owned;
static const char *mode;
static int terminal, cold_waits, signals;
static pid_t fixture_fork(void) {
    pid_t result = fork(); if (result > 0) owned = result; return result;
}
static int fixture_chdir(const char *path) {
    if (getpid() != owner) {
        if (!strcmp(mode, "child-error")) { errno = ENOENT; return -1; }
        for (;;) pause(); /* No executable or network has started. */
    }
    return chdir(path);
}
static pid_t fixture_waitpid(pid_t pid, int *status, int options) {
    if (getpid() == owner && pid == owned && (options & WUNTRACED)) {
        cold_waits++;
        if (!strcmp(mode, "unknown-wait")) { errno = ECHILD; return -1; }
    }
    pid_t result = waitpid(pid, status, options);
    if (getpid() == owner && pid == owned && result == pid && (WIFEXITED(*status) || WIFSIGNALED(*status))) terminal = 1;
    return result;
}
static int fixture_kill(pid_t pid, int signal) {
    if (getpid() == owner && pid == owned && signal == SIGKILL) signals++;
    return kill(pid, signal);
}
static int fixture_clock_gettime(clockid_t clock, struct timespec *now) {
    if (getpid() == owner && owned > 1 && !strcmp(mode, "clock-unavailable")) { errno = EIO; return -1; }
    return clock_gettime(clock, now);
}
#define fork fixture_fork
#define chdir fixture_chdir
#define waitpid fixture_waitpid
#define kill fixture_kill
#define clock_gettime fixture_clock_gettime
#include ${JSON.stringify(launcher)}
#undef fork
#undef chdir
#undef waitpid
#undef kill
#undef clock_gettime
int main(int argc, char **argv) {
    if (argc != 3 || !getuid() || getuid() != geteuid() || getgid() != getegid()) return 2;
    owner = getpid(); mode = argv[1];
    char *arguments[] = {argv[0], NULL}, *environment[] = {"PATH=/usr/bin:/bin", NULL};
    struct envara_child child = {0}; child.error_fd = -1;
    struct timespec before, after; clock_gettime(CLOCK_MONOTONIC, &before);
    int result = envara_spawn_suspended(getuid(), getgid(), argv[2], argv[0], arguments, environment, 1, &child);
    int error = errno; clock_gettime(CLOCK_MONOTONIC, &after);
    long long elapsed = (long long)(after.tv_sec - before.tv_sec) * 1000 + (after.tv_nsec - before.tv_nsec) / 1000000;
    int cleared = !strcmp(mode, "timeout") || !strcmp(mode, "child-error"), status = 0;
    int okay = result == -1 && owned > 1;
    if (cleared) {
        okay = okay && terminal && child.identity.pid == 0 && child.error_fd == -1;
        errno = 0; okay = okay && waitpid(owned, &status, WNOHANG) == -1 && errno == ECHILD;
        if (!strcmp(mode, "timeout")) okay = okay && error == ETIMEDOUT && elapsed >= 4900 && elapsed < 8000 && signals == 1 && cold_waits > 1;
        else okay = okay && error == ENOENT && elapsed < 1000 && !signals;
    } else {
        okay = okay && !terminal && child.identity.pid == owned && child.identity.parent_pid == owner &&
            child.error_fd >= 3 && fcntl(child.error_fd, F_GETFD) >= 0 && elapsed < 1000;
        if (!strcmp(mode, "unknown-wait")) okay = okay && error == ECHILD && !signals;
        else okay = okay && error == EIO;
        /* Teardown only this fixture's actual, unreaped direct child. */
        pid_t done = waitpid(owned, &status, WNOHANG);
        if (!done) { kill(owned, SIGKILL); do { done = waitpid(owned, &status, 0); } while (done < 0 && errno == EINTR); }
        okay = okay && done == owned && (WIFEXITED(status) || WIFSIGNALED(status));
        if (child.error_fd >= 3) close(child.error_fd);
    }
    printf("{\\"ok\\":%s,\\"mode\\":\\"%s\\",\\"clearedOnlyAfterTerminalWait\\":%s,\\"retainedUnknownCustody\\":%s,\\"elapsedMs\\":%lld,\\"ready\\":false,\\"protected\\":false}\\n",
        okay ? "true" : "false", mode, cleared ? "true" : "false", cleared ? "false" : "true", elapsed);
    return okay ? 0 : 1;
}
`, { mode: 0o600 });
      const compiled = spawnSync('xcrun', ['clang', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`, source, '-o', executable],
      { encoding: 'utf8', timeout: 60_000, cwd: temporary });
      assert.equal(compiled.error, undefined);
      assert.equal(compiled.signal, null, compiled.stderr);
      assert.equal(compiled.status, 0, compiled.stderr);
      for (const mode of ['timeout', 'unknown-wait', 'clock-unavailable', 'child-error']) {
        const run = spawnSync(executable, [mode, temporary], { encoding: 'utf8', timeout: 10_000, cwd: temporary });
        assert.equal(run.error, undefined, run.error?.message);
        assert.equal(run.signal, null, `${mode}: ${run.stderr}`);
        assert.equal(run.status, 0, `${mode}: ${run.stdout}\n${run.stderr}`);
        const report = JSON.parse(run.stdout);
        assert.equal(report.ok, true, mode);
        assert.equal(report.clearedOnlyAfterTerminalWait, ['timeout', 'child-error'].includes(mode));
        assert.equal(report.retainedUnknownCustody, ['unknown-wait', 'clock-unavailable'].includes(mode));
        assert.equal(report.ready, false); assert.equal(report.protected, false);
      }
    } finally { rmSync(temporary, { recursive: true, force: true }); }
  });
