#!/bin/sh
set -eu

# Tool fixtures exercise the make dependency graph without a compiler or RPM.
case "${0##*/}" in
go)
    if [ "${RPM_TEST_DELAY_BUILD:-}" = 1 ]; then
        rpm_test_attempts=0
        while [ ! -d .build/rpmbuild/SOURCES ]; do
            rpm_test_attempts=$((rpm_test_attempts + 1))
            if [ "$rpm_test_attempts" -ge 500 ]; then
                printf '%s\n' 'The RPM staging directory did not appear.' >&2
                exit 1
            fi
            sleep 0.01
        done
        sleep 0.1
    fi
    printf 'RPM workflow test binary\n' > telego
    exit 0
    ;;
rpmbuild)
    while [ "$#" -gt 0 ]; do
        if [ "$1" = --define ]; then
            case "$2" in
                '_topdir '*) rpm_test_topdir=${2#* } ;;
                '_app_version_number '*) rpm_test_version=${2#* } ;;
                '_app_version_build '*) rpm_test_release=${2#* } ;;
            esac
            shift
        fi
        shift
    done
    cmp telego "$rpm_test_topdir/SOURCES/telego"
    test -s "$rpm_test_topdir/SPECS/telego.spec"
    for rpm_test_suffix in service sysconfig logrotate permissions tmpfilesd target toml; do
        test -s "$rpm_test_topdir/SOURCES/telego.$rpm_test_suffix"
    done
    mkdir -p "$rpm_test_topdir/RPMS/x86_64"
    printf 'RPM workflow test package\n' > "$rpm_test_topdir/RPMS/x86_64/telego-$rpm_test_version-$rpm_test_release.x86_64.rpm"
    exit 0
    ;;
esac

rpm_test_source=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rpm_test_dir=$(mktemp -d /tmp/telego-rpm-test.XXXXXX)
trap 'rm -rf -- "$rpm_test_dir"' EXIT HUP INT TERM
mkdir -p "$rpm_test_dir/dist" "$rpm_test_dir/bin" "$rpm_test_dir/.build/unrelated"
cp "$rpm_test_source/Makefile" "$rpm_test_dir/Makefile"
cp "$rpm_test_source/config.example.toml" "$rpm_test_dir/config.example.toml"
cp "$rpm_test_source"/dist/rpmbuild.* "$rpm_test_dir/dist/"
cp "$rpm_test_source/dist/test-rpm.sh" "$rpm_test_dir/bin/go"
cp "$rpm_test_source/dist/test-rpm.sh" "$rpm_test_dir/bin/rpmbuild"
chmod +x "$rpm_test_dir/bin/go" "$rpm_test_dir/bin/rpmbuild"
PATH="$rpm_test_dir/bin:$PATH"
export PATH
cd "$rpm_test_dir"

make --no-print-directory -n SHELL=/bin/sh > default.log 2>&1
grep -F 'go build' default.log >/dev/null
if grep -E 'rpmbuild|not found' default.log; then
    printf '%s\n' 'The default target did not select only the Go build.' >&2
    exit 1
fi
make --no-print-directory -s SHELL=/bin/sh
test -s telego
test ! -d .build/rpmbuild

for rpm_test_version in v0.6.0 0.6.0 dev ecf021f; do
    make --no-print-directory -s rpmbuild_environment_set SHELL=/bin/sh VERSION="$rpm_test_version" > version.log 2>&1
    grep -Fx "RPM version: ${rpm_test_version#v}" version.log >/dev/null
    grep -E '^RPM release: [0-9]{8}\.[0-9]{6}\.UTC$' version.log >/dev/null
done
for rpm_test_suffix in 4-gecf021f 4-gecf021f-dirty rc.1; do
    make --no-print-directory -s rpmbuild_environment_set SHELL=/bin/sh VERSION="v0.6.0-$rpm_test_suffix" > version.log 2>&1
    grep -Fx 'RPM version: 0.6.0' version.log >/dev/null
    rpm_test_release=$(printf '%s' "$rpm_test_suffix" | tr - .)
    grep -Fx "RPM release: $rpm_test_release" version.log >/dev/null
done

printf 'unrelated build data\n' > .build/unrelated/keep
mkdir -p .build/rpmbuild/RPMS/x86_64
printf 'stale package\n' > .build/rpmbuild/RPMS/x86_64/stale.rpm
for rpm_test_run in 1 2 3; do
    rm -f telego
    RPM_TEST_DELAY_BUILD=1 make --no-print-directory -s -j8 rpm SHELL=/bin/sh VERSION=v0.6.0-4-gecf021f > parallel.log 2>&1
    test -s telego
    cmp telego .build/rpmbuild/SOURCES/telego
    test -s telego-0.6.0-4.gecf021f.x86_64.rpm
    test -s .build/unrelated/keep
    test ! -f stale.rpm
done
if grep -E 'gnet-(LICENSE|TELEGO)|gnet/(LICENSE|TELEGO)' dist/rpmbuild.mk dist/rpmbuild.spec; then
    printf '%s\n' 'The RPM workflow copied excluded gnet documents.' >&2
    exit 1
fi
printf '%s\n' 'RPM workflow tests passed.'
