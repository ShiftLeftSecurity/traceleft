#!/bin/bash

set -euo pipefail

# We need root for some syscalls
if [[ "$EUID" -ne 0 ]]; then
  echo "Please run the tests as root"
  exit
fi

readonly testdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
outfile=""
pid=-1

while getopts vo: opt; do
  case "$opt" in
    v) set -x ;;
    o) outfile="$OPTARG" ;;
  esac
done

shift $((OPTIND-1))

readonly tempdir=$(mktemp -d /tmp/traceleft-test-cli-XXXXXX)
readonly stampfile="${tempdir}/stamp"
outfile=${outfile:-${tempdir}/outfile}
declare -r outfile
outdir="/tmp/traceleft-trace-out"

function shutdown() {
  if [[ "${pid}" -ne -1 ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill -9 "${pid}" >/dev/null || true
  fi
  rm -f "${outfile}"
  rm -rf "${outdir}"
  rm -rf "${tempdir}"
}

trap shutdown EXIT

printf "Using outfile %s\n" "${outfile}"
printf "Using outdir %s\n" "${outdir}"
mkdir -p "$outdir"

# Make sure tests are up to date
make --silent -C "${testdir}"

host_netns="$(readlink /proc/1/ns/net | cut -d "[" -f2 | cut -d "]" -f1)"

exit_status=0

for dir in "${testdir}"/*; do
    testname=$(basename "${dir}")
    testscript="${testdir}/${testname}/${testname}.script"

    # Only directories starting with test_ contain our tests
    if [[ "${testname}" != test_* ]]; then
        continue
    fi

    if [[ -n $@ ]] && [[ ! " $@ " =~ " ${testname} " ]]; then
        continue
    fi

    "${testdir}/${testname}/${testname}" "${stampfile}" &
    pid=$!
    disown

    status_line="Running ${testname} with PID: ${pid} "
    echo -n "${status_line}"

    testcommands="$(sed -e "s|%PID%|$pid|g" -e "s|%BASEDIR%|${testdir}/../|g" "${testscript}")"

    # wait until the file is created by the test via stampwait()
    until [[ -f "${stampfile}" ]]; do sleep 1; done
    rm -f "${stampfile}"

    echo "${testcommands}" | "${testdir}/cli" --quiet --outfile "${outfile}"

    kill -9 "${pid}" 2>/dev/null || true

    fd=$(cat "$outdir/test_fd" 2>/dev/null || true)
    expected_output="$(sed -e "s|%PID%|$pid|g" "${testdir}/${testname}/expect.log")"
    expected_output="${expected_output//%FD%/$fd}"
    expected_output="${expected_output//%HOST_NETNS%/$host_netns}"

    if diff  --ignore-all-space <(printf "%s" "${expected_output}") "${outfile}"; then
        printf "\r%-50s  \e[32m%-10s\e[39m \n" "${status_line}" "[PASSED]"
    else
        printf "\r%-50s  \e[31m%-10s\e[39m \n" "${status_line}" "[FAILED]"
        exit_status=1
    fi

    rm -f "${outfile}"
done

exit $exit_status
