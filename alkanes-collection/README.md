# Alkane Collection

The collection contract for Alkanes Orbitals.

## Building

```bash
cargo build --target wasm32-unknown-unknown --release
```

The compiled WASM binary will be available in `target/wasm32-unknown-unknown/release/alkanes_collection.wasm`. 

## Deployment

```bash
yarn oyl alkane new-contract -c ./target/alkanes/wasm32-unknown-unknown/release/alkanes_collection.wasm -data 1,0 -p signet
```

## Tracing

```bash
yarn oyl provider alkanes --method trace -params '{"txid":"a1ccb55a8a66b9ddcd4340c6f03bd25c44159a7fe59e663e123c35f2028f7ecc", "vout":3}' -p signet
``` 

### output whitelist
```bash
cargo test test_merkle_generator2 -- --nocapture > test_output.log 2>&1
```