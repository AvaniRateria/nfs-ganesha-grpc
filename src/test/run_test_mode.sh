# Script to run Ganesha for presubmit testing (e.g. pynfs, cthon)
#
# This script is the default way to run Ganesha for testing before submitting
# new code.
#
# Usage:
# 	$ run_test_mode.sh <build_path>
#
# Example:
# 1. Build Ganesha
#	$ cd $(mktemp --directory)
# 	$ cmake ~/git/nfs-ganesha/src
#	$ make
# 2. Run Ganesha:
# 	$ ~/git/nfs-ganesha/src/run_test_mode.sh .
# 3. Run testing:
#	$ cd /opt/pynfs
#	$ ./nfs4.1/testserver.py -v --outfile pynfs-results.log \
#		--maketree 127.0.0.1:/export/test1/pynfs --showomit \
#		--rundeps all ganesha
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <build_path>"
  exit 1
fi

BUILD_PATH="$1"
GANESHA_EXE="$BUILD_PATH/ganesha.nfsd"
if [ ! -f "$GANESHA_EXE" ]; then
  echo "Error: Ganesha executable is missing: $GANESHA_EXE"
  exit 1
fi

# We can't use /tmp because VFS FSAL doesn't support it as export path
# See: https://review.gerrithub.io/c/ffilz/nfs-ganesha/+/555058
mkdir --parents "$HOME/ganesha-test-mode/"
TEMP_DIR=$(mktemp --directory --tmpdir="$HOME/ganesha-test-mode/")

CONFIG_FILE="$TEMP_DIR/conf"
LOG_FILE="$TEMP_DIR/log"
PID_FILE="$TEMP_DIR/pid"
EXPORT_PATH="$TEMP_DIR/export/"

mkdir --parents $EXPORT_PATH
cat << EOF > "$CONFIG_FILE"
NFS_CORE_PARAM {
	Plugins_Dir = "$BUILD_PATH/FSAL/FSAL_VFS/vfs/";
	Protocols = 3, 4;
}
EXPORT_DEFAULTS {
	Access_Type = RW;
}
EXPORT
{
	Export_Id = 1;
	Path = $EXPORT_PATH;
	Pseudo = /export;
	Protocols = 3, 4;
	Access_Type = RW;
	Sectype = sys;
	FSAL {
		Name = VFS;
	}
}
LOG {
	Default_Log_Level = INFO;
}
EOF

set -x
sudo "$GANESHA_EXE" -F -x -f "$CONFIG_FILE" -L "$LOG_FILE" -p "$PID_FILE"
