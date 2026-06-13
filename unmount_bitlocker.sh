#!/usr/bin/env bash
# Unmount the BitLocker drive in reverse order.
#
# Usage: sudo ./unmount_bitlocker.sh

set -euo pipefail

DISLOCKER_MOUNT="${DISLOCKER_MOUNT:-/Volumes/dislocker}"
NTFS_MOUNT="${NTFS_MOUNT:-/Volumes/bitlocker}"

if [[ "${EUID}" -ne 0 ]]; then
	echo "Run as root: sudo $0" >&2
	exit 1
fi

RAW_DISK=""
if [[ -f /tmp/bitlocker_raw_disk ]]; then
	RAW_DISK=$(cat /tmp/bitlocker_raw_disk)
fi

if mount | grep -q " on ${NTFS_MOUNT} "; then
	echo "Unmounting ${NTFS_MOUNT}..."
	umount "${NTFS_MOUNT}"
fi

if [[ -n "${RAW_DISK}" ]] && diskutil info "${RAW_DISK}" &>/dev/null; then
	echo "Detaching ${RAW_DISK}..."
	hdiutil detach "${RAW_DISK}"
fi

if mount | grep -q " on ${DISLOCKER_MOUNT} "; then
	echo "Unmounting ${DISLOCKER_MOUNT}..."
	umount "${DISLOCKER_MOUNT}"
fi

if [[ -f /tmp/bitlocker_dislocker_pid ]]; then
	DISLOCKER_PID=$(cat /tmp/bitlocker_dislocker_pid)
	if kill -0 "${DISLOCKER_PID}" 2>/dev/null; then
		echo "Stopping dislocker-fuse (PID ${DISLOCKER_PID})..."
		kill "${DISLOCKER_PID}"
	fi
	rm -f /tmp/bitlocker_dislocker_pid
fi

rm -f /tmp/bitlocker_raw_disk
echo "Done."
