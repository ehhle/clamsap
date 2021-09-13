#!/bin/sh
cd ..
aclocal
autoconf
autoheader
libtoolize
automake --add-missing
autoreconf --install --force
./configure
make pack
cd ..
mkdir -p ~/rpmbuild
rpmbuild -tb clamsap-*.tar.gz
cp ~/rpmbuild/RPMS/x86_64/clamsap-0.10*.*-1.x86_64.rpm .
