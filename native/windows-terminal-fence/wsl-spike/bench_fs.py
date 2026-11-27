import os, shutil, subprocess, sys, time

root = sys.argv[1]
shutil.rmtree(root, ignore_errors=True)
os.makedirs(root)
env = dict(os.environ, GIT_AUTHOR_NAME='s', GIT_AUTHOR_EMAIL='s@x', GIT_COMMITTER_NAME='s', GIT_COMMITTER_EMAIL='s@x')

def ms(fn):
    t = time.perf_counter(); fn(); return round((time.perf_counter() - t) * 1000)

def create():
    for d in range(20):
        os.makedirs(f'{root}/d{d}')
        for f in range(50):
            with open(f'{root}/d{d}/f{f}.txt', 'w') as h: h.write('x' * 100)

def walk():
    n = 0
    for dp, _, fs in os.walk(root):
        for f in fs: os.stat(os.path.join(dp, f)); n += 1
    assert n == 1000

def git(*a): subprocess.run(['git', '-C', root, *a], check=True, capture_output=True, env=env)

r = {'create': ms(create), 'walk+stat': ms(walk)}
r['git init+add+commit'] = ms(lambda: (git('init', '-q'), git('add', '-A'), git('commit', '-qm', 'x')))
r['git status (avg of 3)'] = round(sum(ms(lambda: git('status', '--porcelain')) for _ in range(3)) / 3)
r['delete'] = ms(lambda: shutil.rmtree(root))
print(root, ' '.join(f'{k}={v}ms' for k, v in r.items()))
