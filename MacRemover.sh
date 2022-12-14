#!/bin/bash
# postinstall - Uninstall MacKeeper

export PATH='/usr/bin:/bin:/usr/sbin:/sbin'

USERS_PATH='/Users'
MACKEEPER_LAUNCHAGENT_PATH=\
'Library/LaunchAgents/com.mackeeper.MacKeeperAgent.plist'
MAX_SECONDS_TO_WAIT_UNTIL_MACKEEPER_STOPS=20
MACKEEPER_APP_PROCESS_NAME='MacKeeper'
MACKEEPER_AGENT_PROCESS_NAME='MacKeeperAgent'
MACKEEPER_PROCESSES_PATTERN='^MacKeeper'
MACKEEPER_SYSTEM_PATHS=(
  '/Applications/MacKeeper.app'
  '/Library/Preferences/.3FAD0F65-FC6E-4889-B975-B96CBF807B78'
)
# These paths will be expanded by a glob (*) suffix on deletion:
MACKEEPER_USER_PATHS=(
  'Library/Application Scripts/com.mackeeper.MacKeeper'
  'Library/Application Support/MacKeeper'
  'Library/Application Support/com.mackeeper.MacKeeper'
  'Library/Caches/com.apple.nsurlsessiond/Downloads/com.mackeeper.MacKeeper'
  'Library/Caches/com.crashlytics.data/com.mackeeper.MacKeeper'
  'Library/Caches/com.mackeeper.MacKeeper'
  'Library/Caches/io.fabric.sdk.mac.data/com.mackeeper.MacKeeper'
  'Library/Containers/com.mackeeper.MacKeeper'
  'Library/LaunchAgents/com.mackeeper.MacKeeper'
  'Library/Logs/MacKeeper'
  'Library/Preferences/com.mackeeper.MacKeeper'
  'Library/Saved Application State/com.mackeeper.MacKeeper'
)
MACKEEPER_PACKAGE_IDENTIFIERS=(
  'com.mackeeper.MacKeeper.pkg'
  'com.mackeeper.MacKeeper.affid.pkg'
)

# Quit MacKeeper.app
pkill -x "${MACKEEPER_APP_PROCESS_NAME}"

# Stop all MacKeeper background processes (MacKeeperAgent)
if pgrep -qx "${MACKEEPER_AGENT_PROCESS_NAME}"; then
  for user in $(users); do
    domain_target="gui/$(id -u "${user}")"
    service_path="${USERS_PATH:?}/${user}/${MACKEEPER_LAUNCHAGENT_PATH:?}"
    launchctl bootout "${domain_target}" "${service_path}"
  done
fi

# Delete MacKeeper system paths
for mackeeper_system_path in "${MACKEEPER_SYSTEM_PATHS[@]}"; do
  rm -rf "${mackeeper_system_path:?}"
done

# Delete MacKeeper user paths for each user
for user_path in "${USERS_PATH:?}"/*; do
  [[ "${user_path##*/}" == 'Shared' ]] && continue # Skip shared user folder
  for mackeeper_user_path in "${MACKEEPER_USER_PATHS[@]}"; do
    rm -rf "${user_path:?}/${mackeeper_user_path:?}"*
  done
done

# Remove MacKeeper packages from package list
for mackeeper_package_identifier in "${MACKEEPER_PACKAGE_IDENTIFIERS[@]}"; do
  pkgutil --forget "${mackeeper_package_identifier:?}"
done

# Removes the rest of artifacts on the machine excluding airwatch files
files=$(mdfind MacKeeper | grep -v '/Library/Application Support/AirWatch/*')

# Perform batch deletion, passing (typically) *all* paths to `sudo rm -rf` *at once*.
printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 sudo rm -rf

# Exit successfully
exit 0
