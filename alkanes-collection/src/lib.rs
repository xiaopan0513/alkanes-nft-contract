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
use std::io::Cursor;
use std::sync::Arc;

mod generation;

/// Template ID for orbital NFT
const ORBITAL_TEMPLATE_ID: u128 = 999906;

/// Name of the NFT collection
const CONTRACT_NAME: &str = "Orbinauts";

/// Symbol of the NFT collection
const CONTRACT_SYMBOL: &str = "Orbinaut";

/// Maximum number of NFTs that can be minted
const MAX_MINTS: u128 = 3600;

/// Maximum number of NFTs that can be purchased in a single transaction during whitelist phase
const WHITELIST_MAX_PURCHASE_PER_TX: u128 = 2;

/// Maximum number of NFTs that can be purchased in a single transaction during public phase
const PUBLIC_MAX_PURCHASE_PER_TX: u128 = 1;

/// Block height at which whitelist minting begins
const WHITELIST_MINT_START_BLOCK: u64 = 253065;

/// Block height at which public minting begins
const PUBLIC_MINT_START_BLOCK: u64 = 253070;

const TAPROOT_SCRIPT_PUBKEY: [u8; 34] = [
    0x51, 0x20, 0x44, 0xa9, 0x58, 0xe6, 0xf9, 0xb5, 0x93, 0xb7,
    0x39, 0x21, 0x75, 0xaf, 0xc5, 0x3a, 0xd9, 0xdb, 0xb2, 0xfc,
    0x05, 0xf9, 0xf4, 0x59, 0xf9, 0x10, 0xae, 0xf8, 0x2e, 0x5c,
    0x35, 0xad, 0x00, 0x49
];

const MERKLE_ROOT: [u8; 32] = [
    0x2f, 0x03, 0xd4, 0x54, 0x18, 0xfa, 0xa3, 0x90,
    0xdd, 0x55, 0xa4, 0x51, 0x6b, 0xcd, 0xf3, 0x70,
    0x6d, 0x7b, 0xc7, 0xef, 0xe5, 0x2d, 0xad, 0x22,
    0xe9, 0xb9, 0xcd, 0x37, 0xcc, 0x00, 0xa4, 0x11
];

const MERKLE_LEAF_COUNT: u128 = 1003;

/// Price per NFT in payment tokens
const BTC_MINT_PRICE: u128 = 10000;

/// Payment option structure
#[derive(Clone)]
struct PaymentOption {
    token_id: AlkaneId,
    price: u128,
}

/// Payment options for minting
const PAYMENT_OPTIONS: [PaymentOption; 2] = [
    PaymentOption {
        token_id: AlkaneId {
            block: 2,
            tx: 1,
        },
        price: 100,
    },
    PaymentOption {
        token_id: AlkaneId {
            block: 2,
            tx: 2,
        },
        price: 100,
    },
];

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
        response.alkanes.0.push(AlkaneTransfer {
            id: context.myself.clone(),
            value: 1u128,
        });

        Ok(response)
    }

    /// Authorized minting function for orbitals
    ///
    /// This function:
    /// 1. Verifies that the caller is the contract owner
    /// 2. Mints the specified number of orbitals
    /// 3. Returns the minted orbital transfers
    ///
    /// # Returns
    /// * `Result<CallResponse>` - Success or failure of minting operation
    fn auth_mint_orbital(&self, count: u128) -> Result<CallResponse> {
        self.only_owner()?;

        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        let mut minted_orbitals = Vec::new();

        // Mint the specified number of orbitals
        for _ in 0..count {
            minted_orbitals.push(self.create_mint_transfer()?);
        }

        response.alkanes.0.extend(minted_orbitals);

        Ok(response)
    }

    /// Get storage pointer for public mint addresses
    fn public_mint_addresses_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/public-mint-addresses")
    }

    /// Check if an address has already minted in public phase
    fn has_public_minted(&self, output_script: &Vec<u8>) -> bool {
        self.public_mint_addresses_pointer().select(output_script).get_value::<u8>() == 1
    }

    /// Mark an address as having minted in public phase
    fn mark_public_minted(&self, output_script: &Vec<u8>) {
        self.public_mint_addresses_pointer().select(output_script).set_value::<u8>(1);
    }

    /// Common pre-mint checks
    ///
    /// Checks:
    /// 1. Total supply limit
    /// 2. Mint start block
    /// 3. Whitelist status
    /// 4. Public mint address restriction
    fn check_mint_prerequisites(&self, count: u128, tx: Option<&Transaction>) -> Result<()> {
        // Check total supply limit
        let index = self.instances_count();
        if index >= self.max_mints() {
            return Err(anyhow!("Minted out"));
        }

        // Check mint start block
        let current_height = self.height();
        
        // Check if we're in whitelist phase
        if current_height >= WHITELIST_MINT_START_BLOCK && current_height < PUBLIC_MINT_START_BLOCK {
            // In whitelist phase, must verify whitelist
            self.verify_minted_pubkey(count, tx)?;
        } else if current_height < WHITELIST_MINT_START_BLOCK {
            return Err(anyhow!("Minting has not started yet. Current block: {}, Whitelist start: {}, Public start: {}", 
                current_height, WHITELIST_MINT_START_BLOCK, PUBLIC_MINT_START_BLOCK));
        } else {
            // In public phase, check if address has already minted
            let tx = match tx {
                Some(tx) => tx.clone(),
                None => consensus_decode::<Transaction>(&mut std::io::Cursor::new(self.transaction()))?,
            };
            let output_script = tx.output[0].script_pubkey.clone().into_bytes().to_vec();
            if self.has_public_minted(&output_script) {
                return Err(anyhow!("Address has already minted in public phase"));
            }
            // Mark address as minted in public phase
            self.mark_public_minted(&output_script);
        }

        Ok(())
    }

    /// Public mint function for orbitals using Alkanes
    fn mint_orbital(&self) -> Result<CallResponse> {
        let context = self.context()?;

        if context.incoming_alkanes.0.len() != 1 {
            return Err(anyhow!("Payments include multiple alkanes"));
        }

        let transfer = context.incoming_alkanes.0[0];
        
        // Find matching payment option
        let payment_option = PAYMENT_OPTIONS.iter()
            .find(|option| option.token_id == transfer.id)
            .ok_or_else(|| anyhow!("Incorrect payment alkanes"))?;

        let (purchase_count, change) = self.calculate_purchase_count(transfer.value, payment_option.price);
        if purchase_count == 0 {
            return Err(anyhow!("Insufficient payment"));
        }

        // Run common pre-mint checks
        self.check_mint_prerequisites(purchase_count, None)?;

        let mut response = CallResponse::default();

        if change > 0 {
            response.alkanes.0.push(AlkaneTransfer {
                id: payment_option.token_id,
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

        let current_height = self.height();
        let max_purchase = if current_height >= WHITELIST_MINT_START_BLOCK && current_height < PUBLIC_MINT_START_BLOCK {
            WHITELIST_MAX_PURCHASE_PER_TX
        } else {
            PUBLIC_MAX_PURCHASE_PER_TX
        };

        let purchase_count = std::cmp::min(btc_amount / BTC_MINT_PRICE, max_purchase);
        if purchase_count == 0 {
            return Err(anyhow!("Insufficient BTC payment"));
        }

        // Run common pre-mint checks
        self.check_mint_prerequisites(purchase_count, Some(&tx))?;

        let mut response = CallResponse::forward(&context.incoming_alkanes);

        for _ in 0..purchase_count {
            response.alkanes.0.push(self.create_mint_transfer()?);
        }

        Ok(response)
    }

    /// Calculate the number of orbitals that can be purchased with the given payment amount
    pub fn calculate_purchase_count(&self, payment_amount: u128, price: u128) -> (u128, u128) {
        let current_height = self.height();
        let max_purchase = if current_height >= WHITELIST_MINT_START_BLOCK && current_height < PUBLIC_MINT_START_BLOCK {
            WHITELIST_MAX_PURCHASE_PER_TX
        } else {
            PUBLIC_MAX_PURCHASE_PER_TX
        };

        let count = payment_amount / price;
        let limited_count = std::cmp::min(count, max_purchase);
        let change = payment_amount - (limited_count * price);
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
        let max_total = self.max_mints();

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
        println!("{}", attributes);  // 输出 JSON 字符串
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

        // Withdraw all payment tokens
        for option in PAYMENT_OPTIONS.iter() {
            let total_balance = self.balance(&context.myself, &option.token_id);
            if total_balance > 0 {
                response.alkanes.0.push(AlkaneTransfer { 
                    id: option.token_id, 
                    value: total_balance 
                });
            }
        }

        Ok(response)
    }

    pub fn script_minted_count_pointer(&self, index: u32) -> StoragePointer {
        StoragePointer::from_keyword(format!("/minted-pubkey-{}", index).as_str())
    }

    pub fn get_script_minted_count(&self, index: u32) -> Result<u128> {
        let pointer = self.script_minted_count_pointer(index);
        let count = pointer.get_value::<u128>();
        Ok(count)
    }

    pub fn add_script_minted_count(&self, index: u32, add_count: u128, limit: u128) -> Result<()> {
        let mut pointer = self.script_minted_count_pointer(index);
        let current_count = pointer.get_value::<u128>();
        let new_count = current_count.checked_add(add_count)
            .ok_or_else(|| anyhow!("minted count overflow"))?;

        if new_count > limit {
            return Err(anyhow!("minted count exceeds limit"));
        }
        pointer.set_value::<u128>(new_count);
        Ok(())
    }

    pub fn verify_minted_pubkey(&self, count: u128, tx: Option<&Transaction>) -> Result<()> {
        let tx = match tx {
            Some(tx) => tx.clone(),
            None => consensus_decode::<Transaction>(&mut std::io::Cursor::new(self.transaction()))?,
        };

        let output_script = tx.output[0]
            .script_pubkey
            .clone()
            .into_bytes()
            .to_vec();

        let mut cursor: Cursor<Vec<u8>> =
            Cursor::<Vec<u8>>::new(find_witness_payload(&tx, 0).ok_or("").map_err(|_| {
                anyhow!("witness envelope at index 0 does not contain data")
            })?);

        let leaf = consume_exact(&mut cursor, output_script.len() + 8)?;
        let leaf_hash = Sha256::hash(&leaf);
        let proof = consume_to_end(&mut cursor)?;
        let mut leaf_cursor = Cursor::new(leaf.clone());
        let script = consume_exact(&mut leaf_cursor, output_script.len())?;
        let index = consume_sized_int::<u32>(&mut leaf_cursor)?;
        let limit = consume_sized_int::<u32>(&mut leaf_cursor)?;

        if script != *output_script {
            return Err(anyhow!("script mismatch"));
        }

        if !MerkleProof::<Sha256>::try_from(proof)?.verify(
            MERKLE_ROOT,
            &[index as usize],
            &[leaf_hash],
            MERKLE_LEAF_COUNT as usize,
        ) {
            return Err(anyhow!("merkle proof invalid"));
        }

        self.add_script_minted_count(index, count, limit as u128)?;
        Ok(())
    }
}

declare_alkane! {
    impl AlkaneResponder for Collection {
        type Message = CollectionMessage;
    }
}
