#!/usr/bin/env bash
# Mount the Windows NTFS drive read-only for malware analysis.
#
# Prerequisites:
#   - ntfs-3g-mac: brew tap gromgit/homebrew-fuse && brew install gromgit/fuse/ntfs-3g-mac
#   - For -drive: dislocker installed (see build_dislocker.sh), macFUSE enabled
#
# Usage:
#   ./mount_bitlocker.sh -file    # pre-decrypted raw NTFS image
#   ./mount_bitlocker.sh -drive   # live BitLocker-encrypted block device
#
#   export BITLOCKER_RECOVERY_PASSWORD='708983-524678-...'   # required for -drive
#
# Override paths/devices:
#   DECRYPTED_BITLOCKER_DRIVE=/path/to/image.raw ./mount_bitlocker.sh -file
#   BITLOCKER_DEVICE=/dev/disk4s3 ./mount_bitlocker.sh -drive

set -euo pipefail

BITLOCKER_DEVICE="${BITLOCKER_DEVICE:-/dev/disk7s3}"
DECRYPTED_BITLOCKER_DRIVE="${DECRYPTED_BITLOCKER_DRIVE:-/Volumes/4tb_storage/bitlocker-decrypted.raw}"
DISLOCKER_MOUNT="${DISLOCKER_MOUNT:-/Volumes/dislocker}"
NTFS_MOUNT_PREFIX="${NTFS_MOUNT_PREFIX:-/Volumes/bitlocker}"

MODE=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	-file)
		if [[ -n "${MODE}" ]]; then
			echo "Specify only one of -file or -drive." >&2
			exit 1
		fi
		MODE="file"
		shift
		;;
	-drive)
		if [[ -n "${MODE}" ]]; then
			echo "Specify only one of -file or -drive." >&2
			exit 1
		fi
		MODE="drive"
		shift
		;;
	-h | --help)
		MODE="help"
		shift
		;;
	*)
		echo "Unknown option: $1" >&2
		MODE="help"
		shift
		;;
	esac
done

usage() {
	cat <<EOF
Usage: $0 -file | -drive

Mount the Windows NTFS volume read-only for malware analysis.

  -file   Mount a pre-decrypted raw NTFS image (no BitLocker).
          Uses DECRYPTED_BITLOCKER_DRIVE
          (default: ${DECRYPTED_BITLOCKER_DRIVE})

  -drive  Mount a BitLocker-encrypted block device via dislocker.
          Uses BITLOCKER_DEVICE (default: ${BITLOCKER_DEVICE})
          Requires BITLOCKER_RECOVERY_PASSWORD.

Current environment:
  BITLOCKER_DEVICE=${BITLOCKER_DEVICE}
  DECRYPTED_BITLOCKER_DRIVE=${DECRYPTED_BITLOCKER_DRIVE}
  NTFS_MOUNT_PREFIX=${NTFS_MOUNT_PREFIX}
  NTFS_MOUNT defaults to \${NTFS_MOUNT_PREFIX}_file (-file) or \${NTFS_MOUNT_PREFIX}_drive (-drive)
EOF
}

if [[ "${MODE}" == "help" ]] || [[ -z "${MODE}" ]]; then
	usage
	exit "$([[ -z "${MODE}" ]] && echo 1 || echo 0)"
fi

NTFS_MOUNT="${NTFS_MOUNT:-${NTFS_MOUNT_PREFIX}_${MODE}}"

find_ntfs_3g() {
	if command -v ntfs-3g &>/dev/null; then
		command -v ntfs-3g
		return 0
	fi

	local brew_ntfs
	brew_ntfs="$(brew --prefix ntfs-3g-mac 2>/dev/null)/bin/ntfs-3g"
	if [[ -x "${brew_ntfs}" ]]; then
		echo "${brew_ntfs}"
		return 0
	fi

	return 1
}

# Read the password while still in the user's shell (before sudo strips the env).
BITLOCKER_RECOVERY_PASSWORD="${BITLOCKER_RECOVERY_PASSWORD:-${bitlocker_recovery_password:-}}"

if [[ "${EUID}" -ne 0 ]]; then
	if ! find_ntfs_3g &>/dev/null; then
		echo "ntfs-3g not found. macOS no longer ships a built-in NTFS driver." >&2
		echo "Install with:" >&2
		echo "  brew tap gromgit/homebrew-fuse" >&2
		echo "  brew install gromgit/fuse/ntfs-3g-mac" >&2
		exit 1
	fi

	if [[ "${MODE}" == "drive" ]]; then
		if [[ -z "${BITLOCKER_RECOVERY_PASSWORD}" ]]; then
			echo "Set BITLOCKER_RECOVERY_PASSWORD (see initial_log.txt)" >&2
			echo "Example: export BITLOCKER_RECOVERY_PASSWORD='708983-524678-...'" >&2
			exit 1
		fi

		# Re-exec as root, passing the password explicitly (sudo clears the env).
		exec sudo env \
			BITLOCKER_RECOVERY_PASSWORD="${BITLOCKER_RECOVERY_PASSWORD}" \
			BITLOCKER_DEVICE="${BITLOCKER_DEVICE}" \
			DECRYPTED_BITLOCKER_DRIVE="${DECRYPTED_BITLOCKER_DRIVE}" \
			DISLOCKER_MOUNT="${DISLOCKER_MOUNT}" \
			NTFS_MOUNT_PREFIX="${NTFS_MOUNT_PREFIX}" \
			NTFS_MOUNT="${NTFS_MOUNT}" \
			"$0" -drive
	fi

	exec sudo env \
		BITLOCKER_DEVICE="${BITLOCKER_DEVICE}" \
		DECRYPTED_BITLOCKER_DRIVE="${DECRYPTED_BITLOCKER_DRIVE}" \
		DISLOCKER_MOUNT="${DISLOCKER_MOUNT}" \
		NTFS_MOUNT_PREFIX="${NTFS_MOUNT_PREFIX}" \
		NTFS_MOUNT="${NTFS_MOUNT}" \
		"$0" -file
fi

NTFS_3G=$(find_ntfs_3g) || {
	echo "ntfs-3g not found. Install gromgit/fuse/ntfs-3g-mac via Homebrew." >&2
	exit 1
}

if mount | grep -q " on ${NTFS_MOUNT} "; then
	echo "Already mounted at ${NTFS_MOUNT}" >&2
	exit 0
fi

mkdir -p "${NTFS_MOUNT}"

mount_file() {
	if [[ ! -f "${DECRYPTED_BITLOCKER_DRIVE}" ]]; then
		echo "Decrypted image not found: ${DECRYPTED_BITLOCKER_DRIVE}" >&2
		echo "Set DECRYPTED_BITLOCKER_DRIVE if needed." >&2
		exit 1
	fi

	echo "Attaching raw NTFS image ${DECRYPTED_BITLOCKER_DRIVE}..."
	local attach_output raw_disk
	attach_output=$(hdiutil attach \
		-imagekey diskimage-class=CRawDiskImage \
		-nomount "${DECRYPTED_BITLOCKER_DRIVE}")
	raw_disk=$(echo "${attach_output}" | awk '/Windows_NTFS/ {print $1; exit}')
	if [[ -z "${raw_disk}" ]]; then
		raw_disk=$(echo "${attach_output}" | awk '/^\/dev\/disk/ {print $1; exit}')
	fi
	if [[ -z "${raw_disk}" ]]; then
		echo "hdiutil attach did not produce a usable block device." >&2
		echo "${attach_output}" >&2
		exit 1
	fi

	echo "Mounting NTFS at ${NTFS_MOUNT} (read-only)..."
	"${NTFS_3G}" -o ro "${raw_disk}" "${NTFS_MOUNT}"

	echo "${raw_disk}" > /tmp/bitlocker_raw_disk
	echo "${NTFS_MOUNT}" > /tmp/bitlocker_ntfs_mount

	echo "Mounted at ${NTFS_MOUNT}"
	echo "  raw image: ${DECRYPTED_BITLOCKER_DRIVE}"
	echo "  block device: ${raw_disk}"
}

mount_drive() {
	if [[ -z "${BITLOCKER_RECOVERY_PASSWORD}" ]]; then
		echo "Internal error: BITLOCKER_RECOVERY_PASSWORD not passed through sudo." >&2
		exit 1
	fi

	if [[ ! -b "${BITLOCKER_DEVICE}" ]]; then
		echo "Block device not found: ${BITLOCKER_DEVICE}" >&2
		echo "Run 'diskutil list' and set BITLOCKER_DEVICE if needed." >&2
		exit 1
	fi

	mkdir -p "${DISLOCKER_MOUNT}"

	echo "Starting dislocker-fuse on ${BITLOCKER_DEVICE} (read-only)..."
	dislocker-fuse -r -V "${BITLOCKER_DEVICE}" -p"${BITLOCKER_RECOVERY_PASSWORD}" -- "${DISLOCKER_MOUNT}" &
	local dislocker_pid=$!

	for _ in $(seq 1 30); do
		if [[ -f "${DISLOCKER_MOUNT}/dislocker-file" ]]; then
			break
		fi
		sleep 1
	done

	if [[ ! -f "${DISLOCKER_MOUNT}/dislocker-file" ]]; then
		echo "dislocker-file did not appear; dislocker-fuse may have failed." >&2
		kill "${dislocker_pid}" 2>/dev/null || true
		exit 1
	fi

	echo "Mounting decrypted NTFS at ${NTFS_MOUNT} (read-only)..."
	"${NTFS_3G}" -o ro "${DISLOCKER_MOUNT}/dislocker-file" "${NTFS_MOUNT}"

	echo "${dislocker_pid}" > /tmp/bitlocker_dislocker_pid
	echo "${NTFS_MOUNT}" > /tmp/bitlocker_ntfs_mount

	echo "Mounted at ${NTFS_MOUNT}"
	echo "  dislocker-fuse PID: ${dislocker_pid}"
}

case "${MODE}" in
file) mount_file ;;
drive) mount_drive ;;
esac
