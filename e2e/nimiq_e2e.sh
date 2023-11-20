#!/bin/bash -e

ps auwx | grep "nodemon" | grep -v grep | awk '{print $2}' | xargs kill || true

COMMIT="master"
BASE_DIR=$(pwd)

# Phase 1
rm -rf snark-setup-coordinator
git clone https://github.com/nimiq/snark-setup-coordinator
pushd snark-setup-coordinator/coordinator-service
git checkout $COMMIT
npm install
npm run build

cp $BASE_DIR/empty_phase1.json ceremony
npm run reset-db
JSON_LOGGING=true COORDINATOR_CONFIG_PATH=ceremony/empty_phase1.json COORDINATOR_AUTH_TYPE=nimiq npm run start-nodemon &
sleep 5
popd

rm -f transcript

echo 1 | RUST_LOG=info cargo run --bin new_ceremony --release -- --phase phase1 --server-url http://localhost:8080 --verifier ba154fac00e55e69ea72bb4966e8f19baf5ad8565e1b67018800b6570828618c --participant 7dfff91466cbe1a42aa9cb613213e6c6d6c012ee03fac0f7512d330fd420d319 --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys --deployer ba154fac00e55e69ea72bb4966e8f19baf5ad8565e1b67018800b6570828618c
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 1 --chunk-size 12 --powers 22 --curve mnt4_753 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 2 --chunk-size 12 --powers 20 --curve mnt6_753 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys

echo 1 | RUST_LOG=info cargo run --release --bin contribute --no-default-features -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-contributor.keys --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin contribute --no-default-features -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-verifier.keys --participation-mode verify --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin control -- --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys --coordinator-url http://localhost:8080 new-round --verify-transcript --expected-participant 7dfff91466cbe1a42aa9cb613213e6c6d6c012ee03fac0f7512d330fd420d319 --new-participant 2238a626c0cbd0c3357da185c438755a2426284abfb293c664f66ce237761a07 --publish --shutdown-delay-time-in-secs 10

echo 1 | RUST_LOG=info cargo run --release --bin contribute --no-default-features -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-contributor-2.keys --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin contribute --no-default-features -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-verifier.keys --participation-mode verify --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin control -- --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys --coordinator-url http://localhost:8080 apply-beacon --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000 --expected-participant 2238a626c0cbd0c3357da185c438755a2426284abfb293c664f66ce237761a07
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release --bin verify_transcript --no-default-features -- --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000
RUST_LOG=info cargo run --release --bin intermediate_transform

# Phase 2
ps auwx | grep "nodemon" | grep -v grep | awk '{print $2}' | xargs kill || true

rm -rf snark-setup-coordinator
git clone https://github.com/nimiq/snark-setup-coordinator
pushd snark-setup-coordinator/coordinator-service
git checkout $COMMIT
npm install
npm run build

cp $BASE_DIR/empty_phase2.json ceremony
npm run reset-db
JSON_LOGGING=true COORDINATOR_CONFIG_PATH=ceremony/empty_phase2.json COORDINATOR_AUTH_TYPE=nimiq npm run start-nodemon &
sleep 5
popd

rm -f transcript

# Copy the phase2_init file appropriately
# MNT4
# 0: macro block, 21 powers
# 1: merger, 21 powers
# 2: pk_tree_1, 21 powers
# 3: pk_tree_3, 21 powers
# 4: pk_tree_5, 22 powers
# MNT6
# 5: macro block wrapper, 19 powers
# 6: merger wrapper, 19 powers
# 7: pk_tree_0, 20 powers
# 8: pk_tree_2, 20 powers
# 9: pk_tree_4, 20 powers
cp setup0_phase2_init mnt4_phase2_init
cp setup1_phase2_init mnt6_phase2_init
mv setup1_phase2_init setup5_phase2_init

cp setup0_phase2_init setup1_phase2_init
cp setup0_phase2_init setup2_phase2_init
cp setup0_phase2_init setup3_phase2_init
cp setup0_phase2_init setup4_phase2_init

cp setup5_phase2_init setup6_phase2_init
cp setup5_phase2_init setup7_phase2_init
cp setup5_phase2_init setup8_phase2_init
cp setup5_phase2_init setup9_phase2_init

echo 1 | RUST_LOG=info cargo run --bin new_ceremony --release -- --phase phase2 --server-url http://localhost:8080 --verifier ba154fac00e55e69ea72bb4966e8f19baf5ad8565e1b67018800b6570828618c --participant 7dfff91466cbe1a42aa9cb613213e6c6d6c012ee03fac0f7512d330fd420d319 --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys --deployer ba154fac00e55e69ea72bb4966e8f19baf5ad8565e1b67018800b6570828618c
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 1 --chunk-size 12 --powers 21 --curve mnt4_753 --circuit-filename macro_block --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 2 --chunk-size 12 --powers 21 --curve mnt4_753 --circuit-filename merger --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 3 --chunk-size 12 --powers 21 --curve mnt4_753 --circuit-filename pk_tree_1 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 4 --chunk-size 12 --powers 21 --curve mnt4_753 --circuit-filename pk_tree_3 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 5 --chunk-size 12 --powers 22 --curve mnt4_753 --circuit-filename pk_tree_5 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 6 --chunk-size 12 --powers 19 --curve mnt6_753 --circuit-filename macro_block_wrapper --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 7 --chunk-size 12 --powers 19 --curve mnt6_753 --circuit-filename merger_wrapper --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 8 --chunk-size 12 --powers 20 --curve mnt6_753 --circuit-filename pk_tree_0 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 9 --chunk-size 12 --powers 20 --curve mnt6_753 --circuit-filename pk_tree_2 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 10 --chunk-size 12 --powers 20 --curve mnt6_753 --circuit-filename pk_tree_4 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys

echo 1 | RUST_LOG=info cargo run --release --bin contribute -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-contributor.keys --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin contribute -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-verifier.keys --participation-mode verify --coordinator-url http://localhost:8080
# Control used to run only 1 round
#echo 1 | RUST_LOG=info cargo run --release --bin control -- -i new_challenge.query -I new_challenge.full --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys --circuit-filenames circuit_mnt4_753 --circuit-filenames circuit_mnt6_753 --coordinator-url http://localhost:8080 apply-beacon --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000 --expected-participant 7dfff91466cbe1a42aa9cb613213e6c6d6c012ee03fac0f7512d330fd420d319
echo 1 | RUST_LOG=info cargo run --release --bin control -- -i new_challenge.query -I new_challenge.full --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys --circuit-filenames circuit_mnt4_753 --circuit-filenames circuit_mnt6_753 --coordinator-url http://localhost:8080 new-round --verify-transcript --expected-participant 7dfff91466cbe1a42aa9cb613213e6c6d6c012ee03fac0f7512d330fd420d319 --new-participant 2238a626c0cbd0c3357da185c438755a2426284abfb293c664f66ce237761a07 --publish --shutdown-delay-time-in-secs 10
echo 1 | RUST_LOG=info cargo run --release --bin contribute -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-contributor-2.keys --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin contribute -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-verifier.keys --participation-mode verify --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin control -- -i new_challenge.query -I new_challenge.full --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys --circuit-filenames circuit_mnt4_753 --circuit-filenames circuit_mnt6_753 --coordinator-url http://localhost:8080 apply-beacon --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000 --expected-participant 2238a626c0cbd0c3357da185c438755a2426284abfb293c664f66ce237761a07
RUST_LOG=info cargo run --release --bin verify_transcript -- --circuit-filenames circuit_mnt4_753 --circuit-filenames circuit_mnt6_753 --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000 -i new_challenge.query -I new_challenge.full

RUST_LOG=info cargo run --release --bin get_keys
