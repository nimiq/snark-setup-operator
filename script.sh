#!/bin/bash

# BASECOMMANDGET="cargo run -r --bin control -- --coordinator-url "https://zkp-ceremony.nimiq.com/" --unsafe-passphrase get-last-contribution-pk -s"
BASECOMMANDREMOVELASTCONTRIBUTION="cargo run -r --bin control -- --coordinator-url "https://zkp-ceremony.nimiq.com/"  --unsafe-passphrase remove-last-contribution --participant-id 61f164f96eef3f5332af30d05c528330fd46f0c67544f68a86389739d5d93bdc -s"

BASECOMMANDPAX="cargo run -r --bin control -- --coordinator-url https://zkp-ceremony.nimiq.com/ --keys-file nimiq.keys --unsafe-passphrase"
PASSPHRASE=""

COMMANDS=(
    # "$BASECOMMANDPAX change-participant-key --old-participant-id 3bc869e03d1a0b344a353497de30a4b9b0d3cc2abdf3c5f0ee74478eae0c51e9 --new-participant-id da26c0c41fbf09de1f2e1249a0b23caeab6fc742356f5d5d291df6ecfcc2d4b5"
    # "$BASECOMMANDPAX change-participant-key --old-participant-id 9a2193fee67dc779cbe5d9dcdc0f50362c50e41b8046ebde37247e7c4cbe2033 --new-participant-id 88228b0521eccbb0bb0be33242c0932a1ff83d00d7c28d61b77f76014c1509ae"
    # "$BASECOMMANDPAX change-participant-key --old-participant-id f8ba6797ca6dc1d1f2e101429ad633a12b56f3cd4a6c9af11794c68ab86e2988 --new-participant-id 761183b1713361ed00716c451bf911b5bcc5ea8ae05bea326e29511a0a92600f"
    # "$BASECOMMANDPAX change-participant-key --old-participant-id f8ba6797ca6dc1d1f2e101429ad633a12b56f3cd4a6c9af11794c68ab86e2988 --new-participant-id 761183b1713361ed00716c451bf911b5bcc5ea8ae05bea326e29511a0a92600f"
    # "$BASECOMMANDPAX change-participant-key --old-participant-id f8ba6797ca6dc1d1f2e101429ad633a12b56f3cd4a6c9af11794c68ab86e2988 --new-participant-id 761183b1713361ed00716c451bf911b5bcc5ea8ae05bea326e29511a0a92600f"
    
    # "$BASECOMMANDPAX remove-participant --participant-id 83b7648d3424f0fa823feae2f6e7f615f9d39ba9f41e4c97d486b25d7defb6b3"
    # "$BASECOMMANDPAX remove-participant --participant-id d6bbd9a33dadbad4ba78bc91f375be52b613e3062f7ae194eaaa2ba736aef97a"
    # "$BASECOMMANDPAX remove-participant --participant-id 9494ca5ba9d42ac8700012f3a01ccc00c75f3eae029fb4602f6d56d4a44620be"
    # "$BASECOMMANDPAX remove-participant --participant-id 8e5def3baba4224e38cdb4c62ecf2912b206590a08da0f1b9540d7596729b4b1"
    # "$BASECOMMANDPAX remove-participant --participant-id 38991d3c10e4f2b8f5fb261cb51190e35c08214594f3ac20be052a6760ae9160"
    # "$BASECOMMANDPAX remove-participant --participant-id 6434a7be819de11e51cdd75d4321e9215ffa90c50cf71d0e65ede0ec3328d226"

    # # Unlocks all verifier locks!
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 94a047c090c9cc84325e3e24473fbe19c57a08af6273c225518191b848da205f"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id b4fdc3ff1840d862b312fc9b9e51215577f902a773e4d20a612c157c6ce3fa26"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 8883ef5d001d965ee2e0a4c439a1fe0e4f449ccba19e94e75ab6f8012b3b02e6"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 4ecec273f735a03a087704cb27b6a3884719080609a600a1a0538ad1b6af29f7"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 15196bd4b52719144efa52df6a6878e0ed24a53e94f589c05ee7094b848412ea"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id c94d89130887b21802feb3aaf68fca6fa05efe6a91c908f80c38206b75eedca4"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 5560837698cf5fd174f53d6b79c6ac95415ff183db5f23259259a320d9a39e22"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id f9cf69c1bb3dcd05e4a88fca626afbdb3fb2e24c841daaa6f6cf2335ff96fc60"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 64fc238f4b3e3f0fe7895e1853d2410a3bd1f2ed916be83084420deb788f580f"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id e95270cd98603bc40682b93d59e9eb63030612c31c6063ca87047cce2770e696"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id fd7e1215f2ad5e162ca8ebf50035f5ca9cd6e0d4f033218eb9cce93ceac91409"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id b99735d6cb4bb001da94933394dc46a40cd25d72f50b086874df61cfeb4080ba"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id ab6bce4b0cd2c1942074aeecff6077121090984bad36c88ef76b0306e117a4b6"
    # Extra verifiers
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 601031367e30871c4edc3b591ac9ea9c6e92f1dcc913755ea55c76bf75153869
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 4b3239056c90f2cfd4b436e829b04caac35ece9670b5f28cd0a9bdaa58e51dad
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id f0fe6c2ccddd493c0e410b2e77f16add2dccf24627b65698ca728a4fe0b67c25
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id d510803073061caff87b12795ba07719096b34cda82ea17aa1415908f7fa929e
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id aa365e2b8b1905f2aaf98f615e50ca9e9bba5340436f8e9649fa196849346a3a
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id ef86b63d999b7ac9251669ec6ba322754ace08a08ab50a5129a0be43b9939c09
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 277c63cf400d0d2064a1aceb79c20ba7d0cf6d34561f6418b5fa57115451c21c
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 3d830d6b2667dbad802c78f10c6c9c0a5f70b50b1496a8db067c3c883507a705
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id e14f10aa2e614ccb0930d12c2be6b52df121984cfc427295254678fab94de21f
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 121c98bcbc4befc531d4ad185ebde1887beacbeda30d1df4411dc853921b44fa

    # Unlocks stuck paxs!
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id be274b484575f6a272589402e26deb969e7d255a0593c6f0874dcf1e2f009a17"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id f5cb118eb16fdb3f2f938c0e3d7013f9df1cd6ffad0193671bb7da8eacb7882c"
    # "$BASECOMMANDPAX unlock-participant-chunks --participant-id 4ecec273f735a03a087704cb27b6a3884719080609a600a1a0538ad1b6af29f7"

    # Remove all corrupt contributions
    # "$BASECOMMANDREMOVELASTCONTRIBUTION 0 -c 862"
    # "$BASECOMMANDREMOVELASTCONTRIBUTION 0 -c 989"
    # "$BASECOMMANDREMOVELASTCONTRIBUTION 0 -c 1516"

    # Round 2 missing paxs
    # "$BASECOMMANDPAX add-participant --participant-id 9a794981f81c6e270f1b412752fced815c58c5887e3ea8ff8a1a577e76d3a13c --participant-id 0a6293eef08d509718a6fca62286d5decf2037968d224bc729417b1463066e3d"
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

