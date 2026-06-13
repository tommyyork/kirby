#!/usr/bin/env bash
# Mount the BitLocker-encrypted Windows drive read-only for malware analysis.
#
# Prerequisites:
#   - dislocker installed (see build_dislocker.sh)
#   - macFUSE cask installed and system extension enabled
#   - ntfs-3g-mac: brew tap gromgit/homebrew-fuse && brew install gromgit/fuse/ntfs-3g-mac
#   - drive connected (verify with: diskutil list)
#
# Usage:
#   export BITLOCKER_RECOVERY_PASSWORD='708983-524678-...'
#   ./mount_bitlocker.sh
#
# Override the device if disk numbering changes:
#   BITLOCKER_DEVICE=/dev/disk4s3 ./mount_bitlocker.sh

set -euo pipefail

BITLOCKER_DEVICE="${BITLOCKER_DEVICE:-/dev/disk4s3}"
DISLOCKER_MOUNT="${DISLOCKER_MOUNT:-/Volumes/dislocker}"
NTFS_MOUNT="${NTFS_MOUNT:-/Volumes/bitlocker}"

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
	if [[ -z "${BITLOCKER_RECOVERY_PASSWORD}" ]]; then
		echo "Set BITLOCKER_RECOVERY_PASSWORD (see initial_log.txt)" >&2
		echo "Example: export BITLOCKER_RECOVERY_PASSWORD='708983-524678-...'" >&2
		exit 1
	fi

	if ! find_ntfs_3g &>/dev/null; then
		echo "ntfs-3g not found. macOS no longer ships a built-in NTFS driver." >&2
		echo "Install with:" >&2
		echo "  brew tap gromgit/homebrew-fuse" >&2
		echo "  brew install gromgit/fuse/ntfs-3g-mac" >&2
		exit 1
	fi

	# Re-exec as root, passing the password explicitly (sudo clears the env).
	exec sudo env \
		BITLOCKER_RECOVERY_PASSWORD="${BITLOCKER_RECOVERY_PASSWORD}" \
		BITLOCKER_DEVICE="${BITLOCKER_DEVICE}" \
		DISLOCKER_MOUNT="${DISLOCKER_MOUNT}" \
		NTFS_MOUNT="${NTFS_MOUNT}" \
		"$0" "$@"
fi

if [[ -z "${BITLOCKER_RECOVERY_PASSWORD}" ]]; then
	echo "Internal error: BITLOCKER_RECOVERY_PASSWORD not passed through sudo." >&2
	exit 1
fi

NTFS_3G=$(find_ntfs_3g) || {
	echo "ntfs-3g not found. Install gromgit/fuse/ntfs-3g-mac via Homebrew." >&2
	exit 1
}

if [[ ! -b "${BITLOCKER_DEVICE}" ]]; then
	echo "Block device not found: ${BITLOCKER_DEVICE}" >&2
	echo "Run 'diskutil list' and set BITLOCKER_DEVICE if needed." >&2
	exit 1
fi

if mount | grep -q " on ${NTFS_MOUNT} "; then
	echo "Already mounted at ${NTFS_MOUNT}" >&2
	exit 0
fi

mkdir -p "${DISLOCKER_MOUNT}" "${NTFS_MOUNT}"

echo "Starting dislocker-fuse on ${BITLOCKER_DEVICE} (read-only)..."
dislocker-fuse -r -V "${BITLOCKER_DEVICE}" -p"${BITLOCKER_RECOVERY_PASSWORD}" -- "${DISLOCKER_MOUNT}" &
DISLOCKER_PID=$!

for _ in $(seq 1 30); do
	if [[ -f "${DISLOCKER_MOUNT}/dislocker-file" ]]; then
		break
	fi
	sleep 1
done

if [[ ! -f "${DISLOCKER_MOUNT}/dislocker-file" ]]; then
	echo "dislocker-file did not appear; dislocker-fuse may have failed." >&2
	kill "${DISLOCKER_PID}" 2>/dev/null || true
	exit 1
fi

echo "Mounting decrypted NTFS at ${NTFS_MOUNT} (read-only)..."
"${NTFS_3G}" -o ro "${DISLOCKER_MOUNT}/dislocker-file" "${NTFS_MOUNT}"

echo "${DISLOCKER_PID}" > /tmp/bitlocker_dislocker_pid

echo "Mounted at ${NTFS_MOUNT}"
echo "  dislocker-fuse PID: ${DISLOCKER_PID}"
