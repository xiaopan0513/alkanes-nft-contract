# Alkanes Image

Create a resource management contract for a single trait component

## Building

```bash
cargo build --target wasm32-unknown-unknown --release
```

The compiled WASM binary will be available in `target/wasm32-unknown-unknown/release/alkanes_image.wasm`. 

## Deployment

```bash
yarn oyl alkane new-contract -c ./target/alkanes/wasm32-unknown-unknown/release/alkanes_nft.wasm -data 1,0 -p oylnet
```

## Tracing

```bash
yarn oyl provider alkanes --method trace -params '{"txid":"88a68a2fcef7139232d858b49ff39f5e50da79a308616ff84a80adf344ea4341", "vout":3}' -p oylnet
``` 