# One-command Apache/PHP Docker reproduction

This local-only recipe builds pristine PHP 8.5.4 as an Apache prefork module on
Debian Bookworm and runs the network-only `../apache_poc.py` driver.

```sh
cd apache-poc/docker
./run.sh
```

Expected command output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux ... x86_64 GNU/Linux
```

Stop and remove it with:

```sh
docker rm -f php-uaf-apache-repro
```

## Reproduction scaffolding

The image intentionally uses one Apache worker, `memory_limit=4M`, and a pinned
minimal PHP build to make allocator placement repeatable. `seed.php` is a
reproduction-only endpoint that creates the required session key/value **before**
the OOM primer; it is not involved in the final control-flow trigger and must
never be deployed publicly.

`discover.py` is a Docker-only bridge that reads addresses from the local
container and passes them to the portable network driver. `run.sh` grants the
container `SYS_PTRACE` solely so this helper can inspect the unprivileged Apache
worker. The driver itself has no process introspection. A real remote path still requires equivalent heap,
module, and libc disclosures plus an application capability to establish the
session value and same-worker request affinity.

The Docker context verifies the PHP source tarball SHA-256:

```text
c1569f1f543f6b025c583cdc0e730e5c5833c603618613f1aa8e75d1524b8c91
```
