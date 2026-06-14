#!/usr/bin/env bash
# Unmount the NTFS volume mounted by mount_bitlocker.sh (-file or -drive).
#
# Usage: sudo ./unmount_bitlocker.sh

set -euo pipefail

DISLOCKER_MOUNT="${DISLOCKER_MOUNT:-/Volumes/dislocker}"
NTFS_MOUNT_PREFIX="${NTFS_MOUNT_PREFIX:-/Volumes/bitlocker}"
NTFS_MOUNT="${NTFS_MOUNT:-}"

if [[ -z "${NTFS_MOUNT}" ]]; then
	if [[ -f /tmp/bitlocker_ntfs_mount ]]; then
		NTFS_MOUNT=$(cat /tmp/bitlocker_ntfs_mount)
	else
		for candidate in \
			"${NTFS_MOUNT_PREFIX}_file" \
			"${NTFS_MOUNT_PREFIX}_drive" \
			/Volumes/bitlocker; do
			if mount | grep -q " on ${candidate} "; then
				NTFS_MOUNT="${candidate}"
				break
			fi
		done
	fi
fi

if [[ -z "${NTFS_MOUNT}" ]]; then
	echo "No BitLocker NTFS mount found. Set NTFS_MOUNT or run mount_bitlocker.sh first." >&2
	exit 1
fi

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

rm -f /tmp/bitlocker_raw_disk /tmp/bitlocker_ntfs_mount
echo "Done."
