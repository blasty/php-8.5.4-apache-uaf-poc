FROM debian:bookworm AS build
ARG PHP_VERSION=8.5.4
ARG PHP_SHA256=c1569f1f543f6b025c583cdc0e730e5c5833c603618613f1aa8e75d1524b8c91
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    apache2 apache2-dev build-essential ca-certificates curl pkg-config xz-utils && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl -fsSLO https://www.php.net/distributions/php-${PHP_VERSION}.tar.xz \
 && echo "${PHP_SHA256}  php-${PHP_VERSION}.tar.xz" | sha256sum -c - \
 && tar -xf php-${PHP_VERSION}.tar.xz --strip-components=1
RUN CFLAGS='-O0 -g3' ./configure --disable-all --with-apxs2=/usr/bin/apxs2 --enable-session --prefix=/opt/php \
 && make -j"$(nproc)"

FROM debian:bookworm
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    apache2 binutils procps python3 && rm -rf /var/lib/apt/lists/* \
 && a2dismod mpm_event && a2enmod mpm_prefork \
 && rm -f /etc/apache2/sites-enabled/000-default.conf \
 && install -d -o www-data -g www-data -m 0770 /opt/php-uaf-lab/sessions/apache-clean
COPY --from=build /src/libs/libphp.so /opt/php-uaf-lab/build/php-8.5.4-apache-clean/libs/libphp.so
COPY apache-php.conf /etc/apache2/conf-enabled/php-repro.conf
COPY mpm_prefork.conf /etc/apache2/mods-available/mpm_prefork.conf
COPY site.conf /etc/apache2/sites-enabled/repro.conf
COPY www/ /opt/php-uaf-lab/www-trace/
COPY discover.py /poc/discover.py
RUN chmod +x /poc/discover.py && echo 'ServerName 127.0.0.1' >>/etc/apache2/apache2.conf
EXPOSE 80
STOPSIGNAL SIGWINCH
CMD ["/usr/sbin/apache2ctl","-D","FOREGROUND"]
