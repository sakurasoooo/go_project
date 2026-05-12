#!/usr/bin/env bash
# SMK-01 … SMK-08 — fast smoke for mdns-survey (see repo plan: mDNS CLI 冒烟测试).
# Does not use `go test ./...` because vendored skill examples under skills/ are not buildable in this module.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> [SMK-01] go test ./cmd/... ./internal/..."
go test ./cmd/... ./internal/...

echo "==> [SMK-02] go build bin/survey"
mkdir -p bin
go build -o bin/survey ./cmd/survey
BIN="${ROOT}/bin/survey"

echo "==> [SMK-03] help exits 0 and lists core flags"
set +e
HELP_OUT="$("${BIN}" --help 2>&1)"
RC=$?
set -e
if [[ "${RC}" -ne 0 ]]; then
  echo "SMK-03: expected exit 0 from --help, got ${RC}" >&2
  echo "${HELP_OUT}" >&2
  exit 1
fi
echo "${HELP_OUT}" | grep -q -- '-cidr' || { echo "SMK-03: missing -cidr in help" >&2; exit 1; }
echo "${HELP_OUT}" | grep -q -- 'ip-range' || { echo "SMK-03: missing ip-range in help" >&2; exit 1; }
echo "${HELP_OUT}" | grep -q -- '-ports' || { echo "SMK-03: missing -ports in help" >&2; exit 1; }
echo "${HELP_OUT}" | grep -q -- '-timeout' || { echo "SMK-03: missing -timeout in help" >&2; exit 1; }
echo "${HELP_OUT}" | grep -q -- '-workers' || { echo "SMK-03: missing -workers in help" >&2; exit 1; }
echo "${HELP_OUT}" | grep -q -- '-iface' || { echo "SMK-03: missing -iface in help" >&2; exit 1; }
echo "${HELP_OUT}" | grep -q -- 'ptr-list' || { echo "SMK-03: missing ptr-list in help" >&2; exit 1; }
echo "${HELP_OUT}" | grep -q -- '-format' || { echo "SMK-03: missing -format in help" >&2; exit 1; }

echo "==> [SMK-04] invalid flags fail (non-zero, message on stderr)"
set +e
OUT="$("${BIN}" --cidr 10.0.0.0/24 --ip-range 10.0.0.1-10 2>&1)"
RC=$?
set -e
if [[ "${RC}" -eq 0 ]]; then
  echo "SMK-04: expected non-zero for mutually exclusive cidr+ip-range" >&2
  exit 1
fi
echo "${OUT}" | grep -qi 'mutually exclusive' || { echo "SMK-04: expected mutually exclusive error, got: ${OUT}" >&2; exit 1; }

set +e
OUT2="$("${BIN}" --cidr 127.0.0.1/32 --workers 0 2>&1)"
RC2=$?
set -e
if [[ "${RC2}" -eq 0 ]]; then
  echo "SMK-04: expected non-zero for --workers 0" >&2
  exit 1
fi
echo "${OUT2}" | grep -qi 'workers' || { echo "SMK-04: expected workers validation, got: ${OUT2}" >&2; exit 1; }

echo "==> [SMK-05] cold targets finish without hang"
# stderr: progress; stdout: report
TMP="$(mktemp)"
set +e
"${BIN}" --cidr 127.0.0.0/31 --ports 5353 --timeout 80ms --workers 4 --enumerate=false >"${TMP}" 2>/dev/null
RC=$?
set -e
if [[ "${RC}" -ne 0 ]]; then
  echo "SMK-05: expected exit 0, got ${RC}" >&2
  cat "${TMP}" >&2 || true
  exit 1
fi

echo "==> [SMK-06] stdout report skeleton (text)"
grep -q '^services:$' "${TMP}" || { echo "SMK-06: missing services:" >&2; cat "${TMP}" >&2; exit 1; }
grep -q '^answers:$' "${TMP}" || { echo "SMK-06: missing answers:" >&2; cat "${TMP}" >&2; exit 1; }
grep -q '^PTR:$' "${TMP}" || { echo "SMK-06: missing PTR:" >&2; cat "${TMP}" >&2; exit 1; }
rm -f "${TMP}"

echo "==> [SMK-07] multi-port list parses and runs"
"${BIN}" --cidr 127.0.0.1/32 --ports 5353-5354,53 --timeout 50ms --workers 8 --enumerate=false >/dev/null 2>&1
"${BIN}" --cidr 127.0.0.1/32 --ports 5353 --timeout 50ms --workers 8 --enumerate=false >/dev/null 2>&1

echo "==> [SMK-08] --format text and yaml"
TMP2="$(mktemp)"
"${BIN}" --cidr 127.0.0.1/32 --ports 5353 --timeout 50ms --workers 4 --enumerate=false --format text >"${TMP2}" 2>/dev/null
grep -q '^services:$' "${TMP2}" || { echo "SMK-08 text: bad output" >&2; cat "${TMP2}" >&2; exit 1; }
rm -f "${TMP2}"

TMP3="$(mktemp)"
"${BIN}" --cidr 127.0.0.1/32 --ports 5353 --timeout 50ms --workers 4 --enumerate=false --format yaml >"${TMP3}" 2>/dev/null
grep -q '^hosts:' "${TMP3}" || { echo "SMK-08 yaml: missing hosts:" >&2; cat "${TMP3}" >&2; exit 1; }
# Cold CI: hosts: []; dev machines may see real Bonjour rows (list items).
if ! grep -qE '^hosts: \[\]' "${TMP3}" && ! grep -q -- '- source:' "${TMP3}"; then
  echo "SMK-08 yaml: expected hosts: [] or at least one list element (- source:)" >&2
  cat "${TMP3}" >&2
  exit 1
fi
rm -f "${TMP3}"

echo "==> All smoke checks passed (SMK-01 … SMK-08)."
