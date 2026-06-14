#!/usr/bin/env bash
# Create a raw NTFS disk image from test/assets/ntfs_test/.
#
# Prerequisites (macOS):
#   brew tap gromgit/homebrew-fuse
#   brew install gromgit/fuse/ntfs-3g-mac
#
# Usage:
#   ./test/assets/create_ntfs_test_image.sh
#   SOURCE_TREE=/path/to/tree OUTPUT_IMAGE=/path/to/image.dd ./test/assets/create_ntfs_test_image.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_TREE="${SOURCE_TREE:-${SCRIPT_DIR}/ntfs_test}"
OUTPUT_IMAGE="${OUTPUT_IMAGE:-${SCRIPT_DIR}/ntfs_test.dd}"
MOUNT_POINT="${MOUNT_POINT:-${SCRIPT_DIR}/.ntfs_test_mount}"
IMAGE_LABEL="${IMAGE_LABEL:-KIRBY_NTFS_TEST}"
IMAGE_PADDING_MB="${IMAGE_PADDING_MB:-64}"

find_mkntfs() {
	if command -v mkntfs &>/dev/null; then
		command -v mkntfs
		return 0
	fi
	for candidate in \
		/opt/homebrew/sbin/mkntfs \
		/usr/local/sbin/mkntfs; do
		if [[ -x "${candidate}" ]]; then
			echo "${candidate}"
			return 0
		fi
	done
	return 1
}

find_ntfs_3g() {
	if command -v ntfs-3g &>/dev/null; then
		command -v ntfs-3g
		return 0
	fi
	for candidate in \
		/opt/homebrew/bin/ntfs-3g \
		/usr/local/bin/ntfs-3g; do
		if [[ -x "${candidate}" ]]; then
			echo "${candidate}"
			return 0
		fi
	done
	return 1
}

usage() {
	cat <<EOF
Usage: $0

Build a raw NTFS image from a directory tree.

Environment overrides:
  SOURCE_TREE       Source directory (default: ${SCRIPT_DIR}/ntfs_test)
  OUTPUT_IMAGE      Output raw image (default: ${SCRIPT_DIR}/ntfs_test.dd)
  MOUNT_POINT       Temporary mount point (default: ${SCRIPT_DIR}/.ntfs_test_mount)
  IMAGE_LABEL       NTFS volume label (default: ${IMAGE_LABEL})
  IMAGE_PADDING_MB  Extra space added above source tree size (default: ${IMAGE_PADDING_MB})
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	usage
	exit 0
fi

if [[ ! -d "${SOURCE_TREE}" ]]; then
	echo "Source tree not found: ${SOURCE_TREE}" >&2
	echo "Populate it first from a mounted Windows volume." >&2
	exit 1
fi

MKNTFS="$(find_mkntfs)" || {
	echo "mkntfs not found. Install ntfs-3g-mac:" >&2
	echo "  brew tap gromgit/homebrew-fuse && brew install gromgit/fuse/ntfs-3g-mac" >&2
	exit 1
}
NTFS_3G="$(find_ntfs_3g)" || {
	echo "ntfs-3g not found. Install ntfs-3g-mac:" >&2
	echo "  brew tap gromgit/homebrew-fuse && brew install gromgit/fuse/ntfs-3g-mac" >&2
	exit 1
}

cleanup_mount() {
	if mount | grep -Fq " on ${MOUNT_POINT} "; then
		umount "${MOUNT_POINT}" || diskutil unmount "${MOUNT_POINT}"
	fi
	rmdir "${MOUNT_POINT}" 2>/dev/null || true
}

trap cleanup_mount EXIT

SOURCE_KB="$(du -sk "${SOURCE_TREE}" | awk '{print $1}')"
SOURCE_MB="$(( (SOURCE_KB + 1023) / 1024 ))"
IMAGE_MB="$(( SOURCE_MB + IMAGE_PADDING_MB ))"
if (( IMAGE_MB < 128 )); then
	IMAGE_MB=128
fi
IMAGE_BYTES="$(( IMAGE_MB * 1024 * 1024 ))"

echo "Source tree: ${SOURCE_TREE} (${SOURCE_MB} MiB)"
echo "Output image: ${OUTPUT_IMAGE} (${IMAGE_MB} MiB)"
echo "Formatting with: ${MKNTFS}"

rm -f "${OUTPUT_IMAGE}"
truncate -s "${IMAGE_BYTES}" "${OUTPUT_IMAGE}"
"${MKNTFS}" -F -L "${IMAGE_LABEL}" -I "${OUTPUT_IMAGE}"

mkdir -p "${MOUNT_POINT}"
cleanup_mount
mkdir -p "${MOUNT_POINT}"

echo "Mounting ${OUTPUT_IMAGE} at ${MOUNT_POINT}"
"${NTFS_3G}" -o local,allow_other "${OUTPUT_IMAGE}" "${MOUNT_POINT}"

echo "Copying source tree into NTFS image"
rsync -a "${SOURCE_TREE}/" "${MOUNT_POINT}/"
sync

echo "Created ${OUTPUT_IMAGE} ($(du -sh "${OUTPUT_IMAGE}" | awk '{print $1}'))"
