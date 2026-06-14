#!/usr/bin/env bash
# Populate test/assets/ntfs_test from a mounted Windows volume.
#
# Usage:
#   ./test/assets/populate_ntfs_test_tree.sh
#   WINDOWS_MOUNT=/Volumes/bitlocker ./test/assets/populate_ntfs_test_tree.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="${DEST:-${SCRIPT_DIR}/ntfs_test}"
WIN="${WINDOWS_MOUNT:-/Volumes/Windows}"

if [[ ! -d "${WIN}" ]]; then
	echo "Windows mount not found: ${WIN}" >&2
	echo "Mount the target volume first or set WINDOWS_MOUNT." >&2
	exit 1
fi

rm -rf "${DEST}"
mkdir -p "${DEST}"

rsync -a "${WIN}/Program Files/WindowsPowerShell/" "${DEST}/Program Files/WindowsPowerShell/"

mkdir -p "${DEST}/Windows/System32"
for dll in \
	DefaultDeviceManager.dll \
	defragres.dll \
	deskadp.dll \
	deskmon.dll \
	apprepapi.dll \
	AuthHostProxy.dll; do
	cp "${WIN}/Windows/System32/${dll}" "${DEST}/Windows/System32/"
done

mkdir -p "${DEST}/Windows/System32/drivers"
for drv in AcpiVpc.sys AppleLowerFilter.sys beep.sys BthA2dp.sys bam.sys bcmfn2.sys; do
	cp "${WIN}/Windows/System32/drivers/${drv}" "${DEST}/Windows/System32/drivers/"
done

mkdir -p "${DEST}/Windows/System32/config"
cp "${WIN}/Windows/System32/config/SYSTEM" "${DEST}/Windows/System32/config/"
cp "${WIN}/Windows/System32/config/SOFTWARE" "${DEST}/Windows/System32/config/"

mkdir -p "${DEST}/Users/riley/Documents" "${DEST}/Users/riley/Downloads"
cp "${WIN}/Users/riley/Documents/desktop.ini" "${DEST}/Users/riley/Documents/"
cp "${WIN}/Users/riley/Downloads/THE CLASSICAL STUDIES MINOR.pdf" \
	"${DEST}/Users/riley/Downloads/"
cp "${WIN}/Users/riley/Downloads/Don Rags Fr. Lang 2021 Spring.docx" \
	"${DEST}/Users/riley/Downloads/"

echo "Populated ${DEST} ($(du -sh "${DEST}" | awk '{print $1}'), $(find "${DEST}" | wc -l | tr -d ' ') paths)"
