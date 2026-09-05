#!/bin/sh
# Run only in a disposable container with native openSUSE dependencies.
# The second RPM must have a higher version and a changed default telego.toml.
set -eu

if [ "${TELEGO_RPM_TEST_CONTAINER:-}" != 1 ] || [ ! -f /.dockerenv ] || [ -d /run/systemd/system ]; then
    printf '%s\n' 'Use a disposable Docker container without a running systemd instance.' >&2
    exit 1
fi
if [ "$#" -ne 2 ] || rpm -q telego >/dev/null 2>&1; then
    printf '%s\n' 'Supply two RPM versions in a container without Telego installed.' >&2
    exit 1
fi
rpm_test_initial=$1
rpm_test_upgrade=$2
rpm_test_dir=$(mktemp -d /tmp/telego-rpm-lifecycle.XXXXXX)

# Use the real systemctl and real RPM scripts. The mask prevents service start.
systemctl mask telego.service
for rpm_test_package in "$rpm_test_initial" "$rpm_test_upgrade"; do
    rpm -qp --scripts "$rpm_test_package" > "$rpm_test_dir/scripts"
    if grep -E '^[[:space:]]*%[[:alpha:]_]' "$rpm_test_dir/scripts"; then
        printf '%s\n' 'An RPM script contains an unexpanded macro.' >&2
        exit 1
    fi
    rpm -qlp "$rpm_test_package" > "$rpm_test_dir/files"
    if grep -E '/gnet/(LICENSE|TELEGO\.md)$' "$rpm_test_dir/files"; then exit 1; fi
done

rpm -Uvh "$rpm_test_initial" > "$rpm_test_dir/install.log" 2>&1
cat "$rpm_test_dir/install.log"
rpm_test_uid=$(id -u telego)
test "$(stat -c '%U:%G:%a' /etc/telego)" = root:telego:750
test "$(stat -c '%U:%G:%a' /etc/telego/telego.toml)" = root:telego:640
test "$(stat -c '%U:%G:%a' /run/telego)" = telego:telego:755
test "$(stat -c '%U:%G:%a' /var/log/telego)" = telego:telego:750
test "$(stat -c '%U:%G:%a' /usr/share/telego)" = telego:telego:700
runuser -u telego -- test -r /etc/telego/telego.toml
runuser -u telego -- test -w /run/telego
runuser -u telego -- test -w /var/log/telego
rpm -V telego

printf '\n# Operator configuration\n' >> /etc/telego/telego.toml
printf '\n# Operator environment\n' >> /etc/sysconfig/telego
cp /etc/telego/telego.toml "$rpm_test_dir/operator.toml"
cp /etc/sysconfig/telego "$rpm_test_dir/operator.sysconfig"
printf 'Operator data\n' > /usr/share/telego/operator-data
chown telego:telego /usr/share/telego/operator-data

# Reproduce the old directory modes before the upgrade repairs them.
chmod 0644 /etc/telego
chmod 0777 /run/telego
chmod 0755 /usr/share/telego

rpm -Uvh "$rpm_test_upgrade" > "$rpm_test_dir/upgrade.log" 2>&1
cat "$rpm_test_dir/upgrade.log"
cmp /etc/telego/telego.toml "$rpm_test_dir/operator.toml"
cmp /etc/sysconfig/telego "$rpm_test_dir/operator.sysconfig"
test -s /etc/telego/telego.toml.rpmnew
test "$(id -u telego)" = "$rpm_test_uid"
test "$(stat -c '%U:%G:%a' /etc/telego/telego.toml)" = root:telego:640
test "$(stat -c '%U:%G:%a' /etc/telego)" = root:telego:750
test "$(stat -c '%U:%G:%a' /run/telego)" = telego:telego:755
test "$(stat -c '%U:%G:%a' /usr/share/telego)" = telego:telego:700
test "$(readlink /etc/systemd/system/telego.service)" = /dev/null

rpm -e telego > "$rpm_test_dir/remove.log" 2>&1
cat "$rpm_test_dir/remove.log"
test ! -e /usr/sbin/telego
cmp /etc/telego/telego.toml.rpmsave "$rpm_test_dir/operator.toml"
cmp /etc/sysconfig/telego.rpmsave "$rpm_test_dir/operator.sysconfig"
test -s /usr/share/telego/operator-data
test "$(id -u telego)" = "$rpm_test_uid"
test "$(readlink /etc/systemd/system/telego.service)" = /dev/null
if grep -E 'scriptlet failed|command not found|%[[:alpha:]_]+: not found' "$rpm_test_dir"/*.log; then
    printf '%s\n' 'An RPM lifecycle script failed.' >&2
    exit 1
fi
printf '%s\n' 'RPM install, upgrade, and removal tests passed with the service masked.'
