use alkanes_collection::Collection;
use bitcoin::Address;
use bitcoin::Network;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof, MerkleTree};
use serde_json;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use wasm_bindgen_test::*;
#[cfg(target_arch = "wasm32")]
use web_sys::console;

macro_rules! test_print {
    ($($arg:tt)*) => {
        #[cfg(target_arch = "wasm32")]
        { console::log_1(&format!($($arg)*).into()) }
        
        #[cfg(not(target_arch = "wasm32"))]
        { println!($($arg)*) }
    };
}

#[wasm_bindgen_test]
fn test_test() {
    let leaf_values = ["a", "b", "c", "d", "e", "f"];
    let leaves: Vec<[u8; 32]> = leaf_values
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let indices_to_prove = vec![3, 4];
    let leaves_to_prove = leaves.get(3..5).ok_or("can't get leaves to prove").unwrap();
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root").unwrap();
    // Serialize proof to pass it to the client
    let proof_bytes = merkle_proof.to_bytes();

    // Parse proof back on the client
    let proof = MerkleProof::<Sha256>::try_from(proof_bytes).unwrap();

    assert!(proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, leaves.len()));
}

#[test]
fn test_merkle_generator() {
    println!("Starting test_merkle_generator");
    let address_list = ["bc1ps0tzpn3m8t8p4qsnx5qsr3ln96ees9rt4xdfn2zxmwz3cvvzsk0qvh87ee",
        "bc1qxuz3y9m0fsxplndksnszqecvwhu8utx8y2zyvf", "193Hnys7HyfeTdhg3pkWxSX3ggCRjC6Pg4"];

    let leaves: Vec<[u8; 32]> = address_list.iter().enumerate()
        .map(|(index, addr)| {
            let address = Address::from_str(addr).expect("Invalid address").require_network(Network::Bitcoin).expect("Wrong network");
            let script = address.script_pubkey();
            let script_bytes = script.as_bytes();

            // Combine script bytes and index
            let mut combined = Vec::new();
            combined.extend_from_slice(script_bytes);
            combined.extend_from_slice(&(index as u32).to_le_bytes());

            // Hash the combined data
            Sha256::hash(&combined)
        })
        .collect();

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let indices_to_prove = vec![0];
    let leaves_to_prove = leaves.get(0..1).ok_or("can't get leaves to prove").unwrap();
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root").unwrap();

    // Serialize proof to pass it to the client
    let proof_bytes = merkle_proof.to_bytes();

    // Parse proof back on the client
    let proof = MerkleProof::<Sha256>::try_from(proof_bytes).unwrap();

    // Verify the original proof
    assert!(proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, leaves.len()));

    // Verify with a specific address
    let verify_address = Address::from_str(&address_list[0]).expect("Invalid address").require_network(Network::Bitcoin).expect("Wrong network");
    let verify_script = verify_address.script_pubkey();
    let mut verify_combined = Vec::new();
    verify_combined.extend_from_slice(verify_script.as_bytes());
    verify_combined.extend_from_slice(&(0u32).to_le_bytes());
    let verify_hash = Sha256::hash(&verify_combined);

    assert!(proof.verify(merkle_root, &[0], &[verify_hash], leaves.len()));
}

#[wasm_bindgen_test]
fn test_merkle_generator2() {
    println!("Starting test_merkle_generator2");
    const WHITELIST_JSON: &str = include_str!("whitelist.json");

    let whitelist: HashMap<String, u32> = serde_json::from_str(WHITELIST_JSON).expect("Invalid JSON");

    let leaves: Vec<[u8; 32]> = whitelist.iter().enumerate()
        .map(|(index, (script, count))| {
            let script_bytes = hex::decode(script).unwrap();

            // Combine script bytes and index
            let mut combined = Vec::new();
            combined.extend_from_slice(&script_bytes);
            combined.extend_from_slice(&(index as u32).to_le_bytes());
            combined.extend_from_slice(&(*count as u32).to_le_bytes());

            // Hash the combined data
            Sha256::hash(&combined)
        })
        .collect();

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root").unwrap();
    test_print!("merkle root: {:?}, length: {}", hex::encode(merkle_root), leaves.len());

    // Create output JSON array
    let mut output_array = Vec::new();
    let mut output_map = serde_json::Map::new();

    for i in 0..leaves.len() {
        let indices_to_prove = vec![i];
        let leaves_to_prove = leaves.get(i..i + 1).ok_or("can't get leaves to prove").unwrap();
        let merkle_proof = merkle_tree.proof(&indices_to_prove);

        // Serialize proof to pass it to the client
        let proof_bytes = merkle_proof.to_bytes();

        // Parse proof back on the client
        let proof = MerkleProof::<Sha256>::try_from(proof_bytes.clone()).unwrap();

        // Verify the original proof
        assert!(proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, leaves.len()));

        let (script, count) = whitelist.iter().nth(i).unwrap();

        let script_bytes = hex::decode(script).unwrap();

        // Combine script bytes and index
        let mut combined = Vec::new();
        combined.extend_from_slice(&script_bytes);
        combined.extend_from_slice(&(i as u32).to_le_bytes());
        combined.extend_from_slice(&(*count as u32).to_le_bytes());

        // Hash the combined data
        let hash = Sha256::hash(&combined);
        assert_eq!(leaves_to_prove[0], hash);

        // Create proof object
        let mut proof_obj = serde_json::Map::new();
        proof_obj.insert("proof".to_string(), json!(hex::encode(proof_bytes)));
        proof_obj.insert("index".to_string(), json!(i));
        proof_obj.insert("limit".to_string(), json!(*count));

        // Add to output map
        output_map.insert(script.clone(), json!(proof_obj));
    }

    // Convert to JSON array
    output_array.push(json!(output_map));
    
    // Print the JSON output using test_print! macro
    test_print!("{}", json!(output_array).to_string());
}

#[wasm_bindgen_test]
fn test_pointer_count() {
    let alkane = Collection::default();
    alkane.add_script_minted_count(947, 5, 5).unwrap();
    assert_eq!(alkane.get_script_minted_count(4).unwrap(), 5u128);
    assert_eq!(alkane.add_script_minted_count(4, 5, 5).is_err(), true);
}