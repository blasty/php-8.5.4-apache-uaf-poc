# PHP 8.5.4 Apache session UAF PoC

> **PRIVATE / EMBARGOED SECURITY RESEARCH** — do not make this repository
> public or deploy its reproduction endpoints on an accessible network.

This repository packages the verified Apache/mod_php reproduction for the
cross-request stale `BG(unserialize)` state reached through
`session.upload_progress`. The demonstrated chain reclaims the stale context,
overwrites the built-in PHP session serializer's decode callback, and reaches
libc `system()` during request startup without an application function-call
trigger.

## Fast local reproduction

Requirements: x86_64 Linux, Docker, Python 3, `curl`, and Internet access while
building the pinned PHP source tarball.

```sh
cd docker
./run.sh
```

The recipe binds Apache only to `127.0.0.1:18086`, builds pristine PHP 8.5.4
from a SHA-256-verified archive, starts one prefork worker, executes the PoC,
and prints:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux ... x86_64 GNU/Linux
```

Remove the reproduction container afterward:

```sh
docker rm -f php-uaf-apache-repro
```

## Repository layout

- `apache_poc.py` — network-only driver; no debugger or process introspection.
- `docker/` — pinned one-command Debian/Apache/PHP reproduction.
- `lab/` — address-assisted validation harness and independent validator.
- `RUN.md` — detailed portable and lab usage.

## Reproduction scaffolding and limitations

The Docker recipe intentionally uses:

- one Apache prefork worker;
- `memory_limit=4M` and deterministic allocator settings;
- `SYS_PTRACE` for the Docker-only address bridge;
- a reproduction-only `seed.php` endpoint to establish the required session
  key/value before the OOM primer.

`seed.php` is not involved in the final control-flow trigger. It must never be
exposed publicly. A non-lab remote path still requires equivalent PHP heap,
module, and libc disclosures, same-worker affinity, and a legitimate way to
establish the crafted session value.

## Verified result

The pristine Apache build passed three fresh-ASLR runs with unique module,
Zend-heap, and libc bases. The independent validator recorded:

```text
VALIDATION=PASS sapi=apache2handler pristine_source_files=7 runs=3 unique_module_heap_libc=3 same_worker=yes sink_symbols=absent natural_target=ps_serializers[1].decode target_offset=0x104a128 libc_system_offset=0x4c490 application_function_call=none
```

