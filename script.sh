#!/bin/bash

# BASECOMMANDGET="cargo run -r --bin control -- --coordinator-url "https://zkp-ceremony.nimiq.com/" --unsafe-passphrase get-last-contribution-pk -s"
# BASECOMMANDREMOVELASTCONTRIBUTION="cargo run -r --bin control -- --coordinator-url "https://zkp-ceremony.nimiq.com/"  --unsafe-passphrase remove-last-contribution --participant-id 854f20fa11449f169b77df25e30dfee71df320fb510603351e205ba8450be8cd -s"

BASECOMMANDPAX="cargo run -r --bin control -- --coordinator-url "https://zkp-ceremony.nimiq.com/" --unsafe-passphrase"
PASSPHRASE=""   #Insert passphrase but never commit to repo.

COMMANDS=(
    # "$BASECOMMANDGET 0 -c 227"
    # "$BASECOMMANDPAX add-participant --participant-id 3fb2444fe574428b4d763d07e71c2a491729e1a48130e94f8ff92f7e13dfba70"
    # "$BASECOMMANDPAX remove-participant --participant-id 1af95f6fde15babea5879079d34a8e504a3406bcae8001b9932b35e0c9f3878d"
    "$BASECOMMANDPAX remove-participant --participant-id 3fb2444fe574428b4d763d07e71c2a491729e1a48130e94f8ff92f7e13dfba70"

)

# Loop through each command
for COMMAND in "${COMMANDS[@]}"; do    
    
    # Loop until the command succeeds
    while true; do
        echo $PASSPHRASE | $COMMAND
    
        # Check the exit status
        if [ $? -eq 0 ]; then
            echo "Command succeeded."
            break
        else
            echo "Command failed. Retrying..."
            sleep 1  # Adjust the sleep time as needed
        fi
    done
done

