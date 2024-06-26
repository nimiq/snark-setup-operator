#!/bin/bash -e

ps auwx | grep "nodemon" | grep -v grep | awk '{print $2}' | xargs kill || true

COMMIT="master"
BASE_DIR=$(pwd)

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
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 1 --chunk-size 12 --powers 12 --curve mnt4_753 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys
echo 1 | RUST_LOG=info cargo run --bin new_setup --release -- --version 2 --chunk-size 8 --powers 12 --curve mnt6_753 --upload-mode direct --server-url http://localhost:8080 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys

echo 1 | RUST_LOG=info cargo run --release --bin contribute --no-default-features -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-contributor.keys --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin contribute --no-default-features -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-verifier.keys --participation-mode verify --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin control -- --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys --coordinator-url http://localhost:8080 new-round --verify-transcript --expected-participant 7dfff91466cbe1a42aa9cb613213e6c6d6c012ee03fac0f7512d330fd420d319 --new-participant 2238a626c0cbd0c3357da185c438755a2426284abfb293c664f66ce237761a07 --publish --shutdown-delay-time-in-secs 10

echo 1 | RUST_LOG=info cargo run --release --bin contribute --no-default-features -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-contributor-2.keys --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin contribute --no-default-features -- --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/nimiq-verifier.keys --participation-mode verify --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release --bin control -- --unsafe-passphrase --keys-file $BASE_DIR/nimiq-verifier.keys --coordinator-url http://localhost:8080 apply-beacon --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000 --expected-participant 2238a626c0cbd0c3357da185c438755a2426284abfb293c664f66ce237761a07
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release --bin verify_transcript --no-default-features -- --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000
RUST_LOG=info cargo run --release --bin intermediate_transform -- --setup-id 0 --circuit-filenames circuit_mnt4_753
RUST_LOG=info cargo run --release --bin intermediate_transform -- --setup-id 1 --circuit-filenames circuit_mnt6_753
mv circuit_mnt4_753_phase2_init setup0_phase2_init
mv circuit_mnt6_753_phase2_init setup1_phase2_init
