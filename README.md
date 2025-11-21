# iplsd

Scan log files for regex patterns containing IP addresses.

Open LOG_FILE; For each line added:
  Match the line with REGEX

When a pattern match produces a new IP_ADDRESS:
  Append IP_ADDRESS to LIST_FILE if not already present
  Write the timeout time into TIMEOUT_DIR/IP_ADDRESS

Every TIMEOUT_INTERVAL: 
  Read IP_ADDRESS (filename) and timeout (content) from TIMEOUT_DIR/*
  If the timeout has expired:
    Remove IP_ADDRESS from WATCHLIST_FILE
    Delete TIMEOUT_DIR/IP_ADDRESS

Use case: maintain IP address list table file for a pf rule
