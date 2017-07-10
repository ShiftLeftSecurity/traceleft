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

outfile=${outfile:-$(mktemp /tmp/traceleft-test-cli-out-XXXXXX)}
declare -r outfile
readonly stampfile="$(mktemp /tmp/traceleft-test-cli-stamp-XXXXXX)"
outdir="/tmp/traceleft-trace-out"

function shutdown() {
  if [[ "${pid}" -ne -1 ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill -9 "${pid}" >/dev/null || true
  fi
  rm -f "${outfile}"
  rm -rf "${outdir}"
  rm -f "${stampfile}"
}

trap shutdown EXIT

printf "Using outfile %s\n" "${outfile}"
printf "Using outdir %s\n" "${outdir}"
mkdir -p "$outdir"

# Make sure tests are up to date
make --silent -C "${testdir}"

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

    until [[ -f "${stampfile}" ]]; do sleep 1; done
    rm -f "${stampfile}"

    echo "${testcommands}" | "${testdir}/cli" --quiet --outfile "${outfile}"

    kill -9 "${pid}" 2>/dev/null || true

    if [[ ("${testname}" == "test_sys_open") ]] || \
       [[ ("${testname}" == "test_sys_close") ]] || \
       [[ ("${testname}" == "test_sys_fchmod") ]] || \
       [[ ("${testname}" == "test_sys_fchown") ]]
    then
        fd=$(cat "$outdir/test_fd")
        expected_output="$(sed -e "s|%PID%|$pid|g; s|%FD%|$fd|g" "${testdir}/${testname}/expect.log")"
    else
        expected_output="$(sed -e "s|%PID%|$pid|g" "${testdir}/${testname}/expect.log")"
    fi

    if diff  --ignore-all-space <(printf "%s" "${expected_output}") "${outfile}"; then
        printf "\r%-50s  \e[32m%-10s\e[39m \n" "${status_line}" "[PASSED]"
    else
        printf "\r%-50s  \e[31m%-10s\e[39m \n" "${status_line}" "[FAILED]"
    fi

    rm -f "${outfile}"
done
