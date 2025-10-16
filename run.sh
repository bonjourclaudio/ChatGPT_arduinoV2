# ...existing code...
#!/bin/bash
set -m

# Directory of this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Set log file location
LOG_FILE="$SCRIPT_DIR/logs/kiosk.log"
mkdir -p "$(dirname "$LOG_FILE")"

# Restart marker file used by USB watcher
RESTART_FILE="$SCRIPT_DIR/.kiosk_restart_request"

# Function for logging
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Redirect all stdout and stderr to log file (avoid process-substitution which can change signal delivery)
exec >>"$LOG_FILE" 2>&1

log "Starting application"

# Change to the directory where this script is located
cd "$SCRIPT_DIR" || exit 1

# Function to check for updates
check_for_updates() {
    log "Checking for updates..."
    
    # Fetch latest changes without modifying local files
    if ! git fetch origin main; then
        log "⚠️ Failed to fetch updates. Continuing with current version."
        return 1
    fi
    # Get the number of commits behind
    COMMITS_BEHIND=$(git rev-list HEAD..origin/main --count)
    
    if [ "$COMMITS_BEHIND" -gt 0 ]; then
        log "📦 Updates available ($COMMITS_BEHIND new commits)"
        
        # Stash any local changes
        if [ -n "$(git status --porcelain)" ]; then
            log "Stashing local changes..."
            git stash
        fi
        
        # Pull updates
        if git pull origin main; then
            log "✅ Updated successfully"
            
            # Install any new dependencies
            log "Checking for new dependencies..."
            npm install
            
            # Update python packages if requirements.txt changed
            if git diff HEAD@{1} HEAD --name-only | grep -q "requirements.txt"; then
                log "📦 Python requirements changed, updating packages..."
                source python/venv/bin/activate
                pip3 install --no-deps -r python/requirements.txt
            fi
            
            # Pop stashed changes if any
            if [ -n "$(git stash list)" ]; then
                log "Restoring local changes..."
                git stash pop
            fi
            
            # Restart the script
            log "🔄 Restarting to apply updates..."
            exec "$0"
        else
            log "⚠️ Update failed. Continuing with current version."
        fi
    else
        log "✅ Already running latest version"
    fi
}

# Check for updates
check_for_updates

# Activate Python virtual environment
if [ -f "$SCRIPT_DIR/python/venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/python/venv/bin/activate"
else
  log "⚠️ Python venv not found at python/venv - continuing without venv activation."
fi

# Function to clean up on exit
cleanup() {
  log "Shutting down servers and cleaning up..."

  # Stop USB watcher if running
  if [[ -n "$WATCHER_PID" ]]; then
    log "Stopping USB watcher (pid: $WATCHER_PID)..."
    kill "$WATCHER_PID" 2>/dev/null || true
    wait "$WATCHER_PID" 2>/dev/null || true
  fi

  # Kill any process using port 3000 or 5173
  log "Killing processes on ports 3000 and 5173..."
  lsof -ti tcp:3000 | xargs kill -9 2>/dev/null || true
  lsof -ti tcp:5173 | xargs kill -9 2>/dev/null || true
  sleep 1

 # Kill backend/frontend (npm) and python scripts
  if [[ -n "$NPM_BACK_PID" ]]; then
    log "Killing npm backend (pid: $NPM_BACK_PID)..."
    kill "$NPM_BACK_PID" 2>/dev/null || true
    wait "$NPM_BACK_PID" 2>/dev/null || true
  fi
  if [[ -n "$NPM_FRONT_PID" ]]; then
    log "Killing npm frontend (pid: $NPM_FRONT_PID)..."
    kill "$NPM_FRONT_PID" 2>/dev/null || true
    wait "$NPM_FRONT_PID" 2>/dev/null || true
  fi
  if [[ -n "$PY_PID" ]]; then
    log "Killing python (pid: $PY_PID)..."
    kill "$PY_PID" 2>/dev/null || true
    wait "$PY_PID" 2>/dev/null || true
  fi

  # Try to kill Chromium by PID
  if [[ -n "$CHROMIUM_PID" ]]; then
    log "Killing chromium (pid: $CHROMIUM_PID)..."
    kill "$CHROMIUM_PID" 2>/dev/null || true
    sleep 1
    if ps -p "$CHROMIUM_PID" > /dev/null 2>&1; then
      kill -9 "$CHROMIUM_PID" 2>/dev/null || true
    fi
  fi

  # Fallback: kill any chromium-browser / Chrome processes
  pkill -f chromium-browser 2>/dev/null || true
  pkill -f "Google Chrome" 2>/dev/null || true
  pkill -o chromium 2>/dev/null || true

  # Final attempt: free ports again
  lsof -ti tcp:3000 | xargs kill -9 2>/dev/null || true
  lsof -ti tcp:5173 | xargs kill -9 2>/dev/null || true

  log "Cleanup complete."
}

# Trap INT/TERM and run cleanup then exit (do not use EXIT here)
trap 'cleanup; exit 0' SIGINT SIGTERM

# Run cleanup at the start to clear old processes
cleanup

if lsof -ti tcp:3000 >/dev/null || lsof -ti tcp:5173 >/dev/null; then
  log "Ports 3000 or 5173 are still in use. Exiting..."
  exit 1
fi

# Setup WiFi permissions only on Raspberry Pi (Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  log "Setting up WiFi management permissions for Raspberry Pi..."
  
  # Check if we need to add the sudoers rule
  if ! sudo -n grep -q "pi ALL=(ALL) NOPASSWD: /usr/bin/nmcli" /etc/sudoers.d/nmcli-pi 2>/dev/null; then
    log "Adding WiFi management permissions..."
    echo "pi ALL=(ALL) NOPASSWD: /usr/bin/nmcli" | sudo tee /etc/sudoers.d/nmcli-pi > /dev/null
    sudo chmod 0440 /etc/sudoers.d/nmcli-pi
    log "WiFi permissions configured."
  else
    log "WiFi permissions already configured."
  fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
  log "Running on macOS - WiFi management not required."
else
  log "Unknown OS type: $OSTYPE - skipping WiFi setup."
fi

# Watcher: looks for new USB mounts that contain a config.js and triggers a restart.
# It will kill the main PID, wait for it to exit, then exec a fresh instance of this script.
watch_for_usb() {
  log "Starting USB watcher..."
  local bases=( "/media/$USER" "/media" "/mnt" "/run/media/$USER" "/Volumes" )
  declare -A seen
  local main_pid="$1"

  while true; do
    for base in "${bases[@]}"; do
      [[ -d "$base" ]] || continue
      while IFS= read -r -d '' cfg; do
        cfg="${cfg%/}"
        if [[ -z "${seen[$cfg]}" ]]; then
          seen[$cfg]=1
          log "📱 Detected USB config: $cfg — requesting restart..."
          # create restart marker for the parent to see
          touch "$RESTART_FILE"
          # signal parent to terminate so it can perform cleanup and then restart
          if [[ -n "$main_pid" ]]; then
            log "Signaling main pid $main_pid to terminate..."
            kill -TERM "$main_pid" 2>/dev/null || true
          fi
          # exit watcher — do not exec from the watcher (avoids race with parent's cleanup)
          log "USB watcher exiting after request."
          return 0
        fi
      done < <(find "$base" -maxdepth 3 -type f -name 'config.js' -print0 2>/dev/null)
    done
    sleep 3
  done
}

# Main runtime function: starts services and kiosk browser
run_once() {
   # Start backend and frontend servers in the background (explicit scripts so we track both)
  log "Starting backend server..."
  npm run start:backend &
  NPM_BACK_PID=$!
  log "Starting frontend server..."
  npm run start:frontend &
  NPM_FRONT_PID=$!

  # Start your Python script(s) in the background (example)
  python python/scriptTTS.py &
  PY_PID=$!

  # Start USB watcher in background (gives it main PID so it can signal termination)
  watch_for_usb "$$" &
  WATCHER_PID=$!

  # Wait for the frontend server to be ready
  log "Waiting for frontend server to be ready on http://localhost:5173 ..."
  until curl -s http://localhost:5173 > /dev/null; do
    sleep 2
  done

  # Launch Chromium in kiosk mode on the attached display
  if [[ "$OSTYPE" == "darwin"* ]]; then
    log "Launching default browser on macOS..."
    open http://localhost:5173 &
  else
    export DISPLAY=:0
    log "Launching Chromium in kiosk mode..."
    
    # Ensure Chromium is configured to not use keyring
    mkdir -p ~/.config/chromium/Default
    if [ ! -f ~/.config/chromium/Default/Preferences ]; then
      cat > ~/.config/chromium/Default/Preferences << EOL
{
  "credentials_enable_service": false,
  "credentials_enable_autosignin": false
}
EOL
    fi
    
    # Define Chromium flags to disable password prompts and other dialogs
    CHROMIUM_FLAGS="--no-sandbox --kiosk --disable-infobars --disable-restore-session-state --disable-features=PasswordManager,GCMChannelStatus --password-store=basic --no-first-run --no-default-browser-check"
    
    sleep 5  # Extra wait for desktop to finish loading
    if command -v chromium >/dev/null 2>&1; then
      chromium $CHROMIUM_FLAGS http://localhost:5173 &
      CHROMIUM_PID=$!
    elif command -v chromium-browser >/dev/null 2>&1; then
      chromium-browser $CHROMIUM_FLAGS http://localhost:5173 &
      CHROMIUM_PID=$!
    else
      log "Chromium browser not found! Please install it with 'sudo apt install chromium' or 'sudo apt install chromium-browser'"
    fi
  fi

  # Wait for background jobs (so trap works). This wait returns when all children exit.
  wait
  log "Background jobs have exited."
}

# Top-level loop: run and restart if the watcher requested one
while true; do
  # Clear previous restart marker
  rm -f "$RESTART_FILE" 2>/dev/null || true

  run_once

  if [ -f "$RESTART_FILE" ]; then
    log "Restart requested by watcher. Re-launching..."
    rm -f "$RESTART_FILE" 2>/dev/null || true
    # small delay to allow ports to free
    sleep 1
    exec "$0"
  else
    log "No restart requested. Exiting main loop."
    break
  fi
done

log "All processes exited. Goodbye!"
# ...existing code...