//! # Alkane Collection Contract
//!
//! This contract implements an NFT collection with the following features:
//! - Premine mechanism for initial token distribution
//! - Block height based minting start control
//! - Lottery-based minting success rate
//! - SVG-based token generation

use alkanes_runtime::{
    declare_alkane, message::MessageDispatch, runtime::AlkaneResponder, storage::StoragePointer,
    token::Token,
};
use metashrew_support::compat::to_arraybuffer_layout;
use metashrew_support::index_pointer::KeyValuePointer;
use metashrew_support::utils::{consume_exact, consume_sized_int, consume_to_end};

use alkanes_support::{
    cellpack::Cellpack, id::AlkaneId,
    parcel::{AlkaneTransfer, AlkaneTransferParcel}, response::CallResponse, witness::find_witness_payload,
};

use crate::generation::svg_generator::SvgGenerator;
use anyhow::{anyhow, Result};
use bitcoin::{Transaction, TxOut};
use metashrew_support::utils::consensus_decode;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof};
use std::collections::HashSet;
use std::io::Cursor;
use std::sync::Arc;

mod generation;

/// Template ID for orbital NFT
const ORBITAL_TEMPLATE_ID: u128 = 999013;

/// Name of the NFT collection
const CONTRACT_NAME: &str = "Orbinauts";

/// Symbol of the NFT collection
const CONTRACT_SYMBOL: &str = "Orbinaut";

/// Maximum number of NFTs that can be minted
const MAX_MINTS: u128 = 3500;

/// Maximum number of NFTs that can be purchased in a single transaction
const MAX_PURCHASE_PER_TX: u128 = 5;

/// Number of NFTs to be premined during contract initialization
/// This value can be set to 0 if no premine is needed
const PREMINE_MINTS: u128 = 100;

/// Block height at which public minting begins
/// If set to 0, minting will be available immediately without block height restriction
const MINT_START_BLOCK: u64 = 0;

/// Price per NFT in payment tokens
const ALKANES_MINT_PRICE: u128 = 50000000000;

const BTC_MINT_PRICE: u128 = 100000;

const TAPROOT_SCRIPT_PUBKEY: [u8; 34] = [
    0x51, 0x20, 0x42, 0xe5, 0xcb, 0x94, 0x70, 0x25, 0x68, 0x2d,
    0xe7, 0xfe, 0x26, 0xf3, 0x9d, 0x52, 0x78, 0x08, 0x83, 0xae,
    0xeb, 0xc8, 0x25, 0x17, 0x37, 0xbd, 0xd4, 0xb3, 0x3b, 0x86,
    0xee, 0x03, 0x72, 0x47
];

/// Payment token ID
const PAYMENT_TOKEN_ID: AlkaneId = AlkaneId {
    block: 2,
    tx: 1,
};

const MERKLE_ROOT: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
];

const MERKLE_LEAF_COUNT: u128 = 0;

/// Collection Contract Structure
/// This is the main contract structure that implements the NFT collection functionality
#[derive(Default)]
pub struct Collection(());

/// Implementation of AlkaneResponder trait for the collection
impl AlkaneResponder for Collection {}

/// Message types for contract interaction
/// These messages define the available operations that can be performed on the contract
#[derive(MessageDispatch)]
enum CollectionMessage {
    /// Initialize the contract and perform premine
    #[opcode(0)]
    Initialize,

    /// Authorized minting operation for orbitals
    #[opcode(69)]
    AuthMintOrbital { index: u128 },

    /// Mint a new orbital NFT
    #[opcode(77)]
    MintOrbital,

    /// Mint a new orbital NFT
    #[opcode(78)]
    MintOrbitalBtc,

    /// Withdraw payment tokens from contract
    #[opcode(80)]
    Withdraw,

    /// Get the name of the collection
    #[opcode(99)]
    #[returns(String)]
    GetName,

    /// Get the symbol of the collection
    #[opcode(100)]
    #[returns(String)]
    GetSymbol,

    /// Get the total supply (minted + premine)
    #[opcode(101)]
    #[returns(u128)]
    GetTotalSupply,

    /// Get the total count of orbitals
    #[opcode(102)]
    #[returns(u128)]
    GetOrbitalCount,

    /// Get the minted count of orbitals
    #[opcode(103)]
    #[returns(u128)]
    GetOrbitalMinted,

    /// Get the per mint amount of orbitals
    #[opcode(104)]
    #[returns(u128)]
    GetValuePerMint,

    /// Get the collection identifier
    #[opcode(998)]
    #[returns(String)]
    GetCollectionIdentifier,

    /// Get SVG data for a specific orbital
    ///
    /// # Arguments
    /// * `index` - The index of the orbital
    #[opcode(1000)]
    #[returns(Vec<u8>)]
    GetData { index: u128 },

    /// Get attributes for a specific orbital
    ///
    /// # Arguments
    /// * `index` - The index of the orbital
    #[opcode(1002)]
    #[returns(String)]
    GetAttributes { index: u128 },
}

/// Implementation of Token trait
impl Token for Collection {
    /// Returns the name of the token collection
    fn name(&self) -> String {
        String::from(CONTRACT_NAME)
    }

    /// Returns the symbol of the token collection
    fn symbol(&self) -> String {
        String::from(CONTRACT_SYMBOL)
    }
}

impl Collection {
    /// Initialize the contract
    ///
    /// initializes all necessary storage values
    ///
    /// # Returns
    /// * `Result<CallResponse>` - Success or failure of initialization
    fn initialize(&self) -> Result<CallResponse> {
        self.observe_initialization()?;

        // Initialize storage values
        self.set_instances_count(0);
        self.set_auth_mint_count(0);

        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        // Collection token acts as auth token for contract minting without any limits
        if PREMINE_MINTS > 0 {
            response.alkanes.0.push(AlkaneTransfer {
                id: context.myself.clone(),
                value: 1u128,
            });
        }

        Ok(response)
    }

    /// Authorized minting function for orbitals
    ///
    /// This function:
    /// 1. Verifies that the caller is the contract owner
    /// 2. Checks if PREMINE_MINTS is greater than 0
    /// 3. Checks if the requested mint count plus current auth mint count doesn't exceed PREMINE_MINTS
    /// 4. Mints the specified number of orbitals
    /// 5. Returns the minted orbital transfers
    ///
    /// # Returns
    /// * `Result<CallResponse>` - Success or failure of minting operation
    fn auth_mint_orbital(&self, count: u128) -> Result<CallResponse> {
        self.only_owner()?;

        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        // Check if PREMINE_MINTS is greater than 0
        if PREMINE_MINTS == 0 {
            return Err(anyhow!("Premine minting is not enabled (PREMINE_MINTS is 0)"));
        }

        // Check if the requested mint count plus current auth mint count doesn't exceed PREMINE_MINTS
        let current_auth_mints = self.get_auth_mint_count();
        let new_auth_mints = current_auth_mints.checked_add(count)
            .ok_or_else(|| anyhow!("Auth mint count would overflow"))?;

        if new_auth_mints > PREMINE_MINTS {
            return Err(anyhow!("Requested mint count {} plus current auth mints {} would exceed premine limit of {}", 
                count, current_auth_mints, PREMINE_MINTS));
        }

        let mut minted_orbitals = Vec::new();

        // Mint the specified number of orbitals
        for _ in 0..count {
            minted_orbitals.push(self.create_mint_transfer()?);
        }

        // Update the auth mint count
        self.set_auth_mint_count(new_auth_mints);

        response.alkanes.0.extend(minted_orbitals);

        Ok(response)
    }

    /// Public mint function for orbitals using Alkanes
    fn mint_orbital(&self) -> Result<CallResponse> {
        let context = self.context()?;

        if context.incoming_alkanes.0.len() != 1 {
            return Err(anyhow!("Payments include multiple alkanes"));
        }

        let transfer = context.incoming_alkanes.0[0];
        if transfer.id != PAYMENT_TOKEN_ID {
            return Err(anyhow!("Incorrect payment alkanes"));
        }

        let (purchase_count, change) = self.calculate_purchase_count(transfer.value);
        if purchase_count == 0 {
            return Err(anyhow!("Insufficient payment"));
        }

        // Run common pre-mint checks
        self.check_mint_prerequisites(purchase_count)?;

        let mut response = CallResponse::default();

        if change > 0 {
            response.alkanes.0.push(AlkaneTransfer {
                id: PAYMENT_TOKEN_ID,
                value: change,
            });
        }

        for _ in 0..purchase_count {
            response.alkanes.0.push(self.create_mint_transfer()?);
        }

        Ok(response)
    }

    /// Public mint function for orbitals using BTC
    fn mint_orbital_btc(&self) -> Result<CallResponse> {
        let context = self.context()?;

        let tx = consensus_decode::<Transaction>(&mut std::io::Cursor::new(self.transaction()))
            .map_err(|e| anyhow!("Failed to parse Bitcoin transaction: {}", e))?;
        let btc_amount = self.compute_btc_output(&tx);

        // Check if payment was provided
        if btc_amount < BTC_MINT_PRICE {
            return Err(anyhow!("BTC payment amount {} below minimum {}", btc_amount, BTC_MINT_PRICE));
        }

        let purchase_count = std::cmp::min(btc_amount / BTC_MINT_PRICE, MAX_PURCHASE_PER_TX);
        if purchase_count == 0 {
            return Err(anyhow!("Insufficient BTC payment"));
        }

        // Run common pre-mint checks
        self.check_mint_prerequisites(purchase_count)?;

        let mut response = CallResponse::forward(&context.incoming_alkanes);

        for _ in 0..purchase_count {
            response.alkanes.0.push(self.create_mint_transfer()?);
        }

        Ok(response)
    }

    /// Common pre-mint checks
    ///
    /// Checks:
    /// 1. Total supply limit
    /// 2. Mint start block
    /// 3. Whitelist status
    fn check_mint_prerequisites(&self, count: u128) -> Result<()> {
        // Check total supply limit
        let index = self.instances_count();
        if index >= (self.max_mints() + PREMINE_MINTS) {
            return Err(anyhow!("Minted out"));
        }

        // Check mint start block
        let current_height = self.height();
        if MINT_START_BLOCK > 0 {
            if current_height < MINT_START_BLOCK {
                return Err(anyhow!("Minting has not started yet. Current block: {}, Start block: {}", current_height, MINT_START_BLOCK));
            }
        }

        // Check whitelist
        self.verify_minted_pubkey(count)?;

        Ok(())
    }

    /// Calculate the number of orbitals that can be purchased with the given payment amount
    pub fn calculate_purchase_count(&self, payment_amount: u128) -> (u128, u128) {
        let count = payment_amount / ALKANES_MINT_PRICE;
        let limited_count = std::cmp::min(count, MAX_PURCHASE_PER_TX);
        let change = payment_amount - (limited_count * ALKANES_MINT_PRICE);
        (limited_count, change)
    }

    /// Compute the total output value sent to the taproot address
    fn compute_btc_output(&self, tx: &Transaction) -> u128 {
        let total = tx.output.iter().fold(0, |r: u128, v: &TxOut| -> u128 {
            if v.script_pubkey.as_bytes().to_vec() == TAPROOT_SCRIPT_PUBKEY {
                r + <u64 as Into<u128>>::into(v.value.to_sat())
            } else {
                r
            }
        });

        total
    }

    /// Create a mint transfer
    ///
    /// # Returns
    /// * `Result<AlkaneTransfer>` - The transfer object or error
    fn create_mint_transfer(&self) -> Result<AlkaneTransfer> {
        let index = self.instances_count();
        let max_total = self.max_mints().checked_add(PREMINE_MINTS)
            .ok_or_else(|| anyhow!("Max total calculation overflow"))?;

        if index >= max_total {
            return Err(anyhow!("Minted out"));
        }

        let cellpack = Cellpack {
            target: AlkaneId {
                block: 6,
                tx: ORBITAL_TEMPLATE_ID,
            },
            inputs: vec![0x0, index],
        };

        let sequence = self.sequence();
        let response = self.call(&cellpack, &AlkaneTransferParcel::default(), self.fuel())?;

        let orbital_id = AlkaneId {
            block: 2,
            tx: sequence,
        };

        self.add_instance(&orbital_id)?;

        if response.alkanes.0.len() < 1 {
            Err(anyhow!("orbital token not returned with factory"))
        } else {
            Ok(response.alkanes.0[0])
        }
    }

    /// Get maximum number of mints allowed
    ///
    /// # Returns
    /// * `u128` - Maximum number of tokens that can be minted
    fn max_mints(&self) -> u128 {
        MAX_MINTS
    }

    /// Get the pointer to the taproot address
    pub fn taproot_address_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/taproot-address")
    }

    /// Get the taproot address script
    pub fn taproot_address_script(&self) -> Vec<u8> {
        self.taproot_address_pointer().get().as_ref().clone()
    }

    /// Verify that the caller is the contract owner using collection token
    ///
    /// # Returns
    /// * `Result<()>` - Success or error if not owner
    fn only_owner(&self) -> Result<()> {
        let context = self.context()?;

        if context.incoming_alkanes.0.len() != 1 {
            return Err(anyhow!("did not authenticate with only the collection token"));
        }

        let transfer = context.incoming_alkanes.0[0].clone();
        if transfer.id != context.myself.clone() {
            return Err(anyhow!("supplied alkane is not collection token"));
        }

        if transfer.value < 1 {
            return Err(anyhow!("less than 1 unit of collection token supplied to authenticate"));
        }

        Ok(())
    }

    /// Get storage pointer for authorized mint count
    fn get_auth_mint_count_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/auth_mint_count")
    }

    /// Get authorized mint count
    fn get_auth_mint_count(&self) -> u128 {
        self.get_auth_mint_count_pointer().get_value()
    }

    /// Set authorized mint count
    fn set_auth_mint_count(&self, count: u128) {
        self.get_auth_mint_count_pointer().set_value(count);
    }

    /// Get instance storage pointer
    ///
    /// # Returns
    /// * `StoragePointer` - Pointer to instance storage
    fn instances_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/instances")
    }

    /// Get total number of instances
    ///
    /// # Returns
    /// * `u128` - Current instance count
    fn instances_count(&self) -> u128 {
        self.instances_pointer().get_value::<u128>()
    }

    /// Set total number of instances
    ///
    /// # Arguments
    /// * `count` - New instance count
    fn set_instances_count(&self, count: u128) {
        self.instances_pointer().set_value::<u128>(count);
    }

    /// Add a new instance
    ///
    /// # Arguments
    /// * `instance_id` - ID of the new instance
    ///
    /// # Returns
    /// * `Result<u128>` - New instance count or error
    fn add_instance(&self, instance_id: &AlkaneId) -> Result<u128> {
        let count = self.instances_count();
        let new_count = count.checked_add(1)
            .ok_or_else(|| anyhow!("instances count overflow"))?;

        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&instance_id.block.to_le_bytes());
        bytes.extend_from_slice(&instance_id.tx.to_le_bytes());

        let bytes_vec = new_count.to_le_bytes().to_vec();
        let mut instance_pointer = self.instances_pointer().select(&bytes_vec);
        instance_pointer.set(Arc::new(bytes));

        self.set_instances_count(new_count);

        Ok(new_count)
    }

    /// Get the name of the collection
    fn get_name(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = self.name().into_bytes();

        Ok(response)
    }

    /// Get the symbol of the collection
    fn get_symbol(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = self.symbol().into_bytes();

        Ok(response)
    }

    /// Get the total supply of tokens
    /// Returns the total number of minted tokens (including premine)
    fn get_total_supply(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        // Total supply is the current instances count
        response.data = self.instances_count().to_le_bytes().to_vec();

        Ok(response)
    }

    /// Get the total count of orbitals
    fn get_orbital_count(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = MAX_MINTS.to_le_bytes().to_vec();

        Ok(response)
    }

    /// Get the mint per amount of orbitals
    fn get_value_per_mint(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = 1u128.to_le_bytes().to_vec();

        Ok(response)
    }

    /// Get the minted count of orbitals
    fn get_orbital_minted(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        // Calculate actual minted count = total instances count - authorized mint count
        let minted_count = self.instances_count().saturating_sub(self.get_auth_mint_count());
        response.data = minted_count.to_le_bytes().to_vec();

        Ok(response)
    }

    /// Get the collection identifier
    /// Returns the collection identifier in the format "block:tx"
    fn get_collection_identifier(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        // Format the collection identifier as "block:tx"
        let identifier = format!("{}:{}", context.myself.block, context.myself.tx);
        response.data = identifier.into_bytes();

        Ok(response)
    }

    /// Get data for a specific orbital
    fn get_data(&self, index: u128) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        let svg = SvgGenerator::generate_svg(index)?;
        response.data = svg.into_bytes();
        Ok(response)
    }

    /// Get attributes for a specific orbital
    fn get_attributes(&self, index: u128) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        let attributes = SvgGenerator::get_attributes(index)?;
        response.data = attributes.into_bytes();
        Ok(response)
    }

    /// Withdraw payment tokens from contract
    ///
    /// This function:
    /// 1. Verifies that the caller is the contract owner using collection token
    /// 2. Transfers all payment tokens to the caller
    ///
    /// # Returns
    /// * `Result<CallResponse>` - Success or failure of withdrawal operation
    fn withdraw(&self) -> Result<CallResponse> {
        self.only_owner()?;

        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        let total_balance = self.balance(&context.myself, &PAYMENT_TOKEN_ID);
        if total_balance > 0 {
            response.alkanes.0.push(AlkaneTransfer { id: context.myself.clone(), value: total_balance });
        }

        Ok(response)
    }

    fn minted_pubkey_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/minted-pubkey")
    }

    fn get_minted_pubkey_set(&self) -> Result<HashSet<Vec<u8>>> {
        let data = self.minted_pubkey_pointer().get();
        if data.as_ref().is_empty() {
            Ok(HashSet::new())
        } else {
            serde_json::from_slice(data.as_ref())
                .map_err(|e| anyhow!("Failed to deserialize whitelist: {}", e))
        }
    }

    fn save_minted_pubkey_set(&self, minted_set: &HashSet<Vec<u8>>) -> Result<()> {
        let json = serde_json::to_vec(minted_set)
            .map_err(|e| anyhow!("Failed to serialize whitelist: {}", e))?;
        self.minted_pubkey_pointer().set(Arc::new(json));
        Ok(())
    }

    fn script_minted_count_pointer(&self,index:u32) -> StoragePointer {
        StoragePointer::from_keyword(format!("/minted-pubkey-{}", index).as_str())
    }

    fn add_script_minted_count(&self,index:u32, add_count:u128,limit: u128) -> Result<()> {
        let mut pointer = self.script_minted_count_pointer(index);
        let current_count = pointer.get_value::<u128>();
        let new_count = current_count.checked_add(add_count).ok_or_else(|| anyhow!("minted count overflow"))?;
        if new_count > limit {
            return Err(anyhow!("minted count exceeds limit"));
        }
        pointer.set_value::<u128>(new_count);
        Ok(())
    }

    //用这个替换check_whitelist 就是用merkle proof 验证
    pub fn verify_minted_pubkey(&self, count: u128) -> Result<bool> {
        let context = self.context()?;
        let tx = consensus_decode::<Transaction>(&mut std::io::Cursor::new(self.transaction()))?;

        let output_script = tx.output[0]
            .script_pubkey
            .clone()
            .into_bytes()
            .to_vec();

        let mut cursor: Cursor<Vec<u8>> =
        Cursor::<Vec<u8>>::new(find_witness_payload(&tx, 0).ok_or("").map_err(|_| {
            anyhow!("merkle-distributor: witness envelope at index 0 does not contain data")
        })?);

        let leaf = consume_exact(&mut cursor, output_script.len() + 8)?;
        let leaf_hash = Sha256::hash(&leaf);
        let proof = consume_to_end(&mut cursor)?;
        let mut leaf_cursor = Cursor::new(leaf.clone());
        let script = consume_exact(&mut leaf_cursor, output_script.len())?;
        let index = consume_sized_int::<u32>(&mut leaf_cursor)?;
        let limit = consume_sized_int::<u32>(&mut leaf_cursor)?;

    
        if script == output_script {
            if MerkleProof::<Sha256>::try_from(proof)?.verify(
                MERKLE_ROOT,
                &[index as usize],
                &[leaf_hash],
                MERKLE_LEAF_COUNT as usize,
            ) {
                let new_balance = self.balance(&context.caller, &context.myself).checked_add(count).ok_or_else(|| anyhow!("balance overflow"))?;
                if new_balance > limit as u128 {
                    return Err(anyhow!("minted count exceeds limit"));
                } else {
                    Ok(true)
                }
                //不确定上面余额校验的逻辑是否正确。 如果有问题的话，需要用下面的逻辑
                // self.add_script_minted_count(index, count, limit as u128)?;
            } else {
                Err(anyhow!("proof verification failure"))
            }
        } else {
            Err(anyhow!("output_script does not match proof"))
        }

    }
}

declare_alkane! {
    impl AlkaneResponder for Collection {
        type Message = CollectionMessage;
    }
}
