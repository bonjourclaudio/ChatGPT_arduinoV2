#!/bin/bash

URL="ws://localhost:3000"

while true; do
  echo "Sending 'checkFish' to $URL"
  echo "checkFish" | websocat "$URL"
  sleep 300  # wait 5 minutes (300 seconds)
done
