//! # Alkane Collection Contract
//!
//! This contract implements an NFT collection with the following features:
//! - Premine mechanism for initial token distribution
//! - Block height based minting start control
//! - Lottery-based minting success rate
//! - SVG-based token generation

use metashrew_support::index_pointer::KeyValuePointer;
use metashrew_support::compat::to_arraybuffer_layout;
use alkanes_runtime::{
    declare_alkane, message::MessageDispatch, storage::StoragePointer, token::Token,
    runtime::AlkaneResponder,
};

use alkanes_support::{
    cellpack::Cellpack, id::AlkaneId,
    parcel::{AlkaneTransfer, AlkaneTransferParcel}, response::CallResponse,
};

use anyhow::{anyhow, Result};
use std::sync::Arc;
use bitcoin::{Script, Transaction, TxOut};
use metashrew_support::utils::consensus_decode;
use protorune_support::network::{to_address_str};
use crate::generation::svg_generator::SvgGenerator;
use ordinals::{Artifact, Runestone};
use protorune_support::{protostone::Protostone};
use hex;

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

const TAPROOT_SCRIPT_PUBKEY: [u8;34] = [
    0x51, 0x20, 0x42, 0xe5, 0xcb, 0x94, 0x70, 0x25, 0x68, 0x2d,
    0xe7, 0xfe, 0x26, 0xf3, 0x9d, 0x52, 0x78, 0x08, 0x83, 0xae,
    0xeb, 0xc8, 0x25, 0x17, 0x37, 0xbd, 0xd4, 0xb3, 0x3b, 0x86,
    0xee, 0x03, 0x72, 0x47
];

const WHITELIST_JSON: &str = include_str!("whitelist.json");

/// Payment token ID
const PAYMENT_TOKEN_ID: AlkaneId = AlkaneId {
    block: 2,
    tx: 2,
};

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

    #[opcode(81)]
    SetTaprootAddress { part1: u128, part2: u128, part3: u128 },

    #[opcode(82)]
    #[returns(String)]
    GetTaprootAddress,

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

    /// Public mint function for orbitals
    ///
    /// # Returns
    /// * `Result<CallResponse>` - Success or failure of minting operation
    fn mint_orbital(&self) -> Result<CallResponse> {
        let context = self.context()?;

        let index = self.instances_count();
        if index >= (self.max_mints() + PREMINE_MINTS) {
            return Err(anyhow!("Minted out"));
        }

        let current_height = self.height();
        if MINT_START_BLOCK > 0 {
            if current_height < MINT_START_BLOCK {
                return Err(anyhow!("Minting has not started yet. Current block: {}, Start block: {}", current_height, MINT_START_BLOCK));
            }
        }

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

        let whitelist_result = self.check_whitelist(context.vout)?;
        if !whitelist_result {
            return Err(anyhow!("spendable output not in whitelist"));
        }
        
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

    /// Calculate the number of orbitals that can be purchased with the given payment amount
    pub fn calculate_purchase_count(&self, payment_amount: u128) -> (u128, u128) {
        let count = payment_amount / ALKANES_MINT_PRICE;
        let limited_count = std::cmp::min(count, MAX_PURCHASE_PER_TX);
        let change = payment_amount - (limited_count * ALKANES_MINT_PRICE);
        (limited_count, change)
    }

    /// Compute the total output value sent to the taproot address
    fn compute_btc_output(&self, tx: &Transaction) -> u128 {
        let taproot_script = self.taproot_address_script();
        if taproot_script.is_empty() {
            return 0;
        }

        let total = tx.output.iter().fold(0, |r: u128, v: &TxOut| -> u128 {
            if v.script_pubkey.as_bytes().to_vec() == TAPROOT_SCRIPT_PUBKEY {
                r + <u64 as Into<u128>>::into(v.value.to_sat())
            } else {
                r
            }
        });

        total
    }

    pub fn check_whitelist(&self, vout: u32) -> Result<bool> {
        let whitelist: Vec<String> = serde_json::from_str(WHITELIST_JSON).unwrap();
        let tx = consensus_decode::<Transaction>(&mut std::io::Cursor::new(self.transaction()))?;
        if let Some(Artifact::Runestone(ref runestone)) = Runestone::decipher(&tx) {
            let protostones = Protostone::from_runestone(runestone)?;
            let message = &protostones[(vout as usize) - tx.output.len() - 1];
            if message.edicts.len() != 0 {
                panic!("message cannot contain edicts, only a pointer")
            }
            let pointer = message
                .pointer
                .ok_or("")
                .map_err(|_| anyhow!("no pointer in message"))?;
            if pointer as usize >= tx.output.len() {
                panic!("pointer cannot be a protomessage");
            }
            
            let p2sh = tx.output[(pointer as usize) as usize]
            .script_pubkey
            .clone()
            .into_bytes()
            .to_vec();
        
            if !whitelist.contains(&hex::encode(p2sh)) {
                Err(anyhow!("spendable output not in whitelist"))
            } else {
                Ok(true)
            }
            
        } else {
            Err(anyhow!("runestone decipher failed"))
        }
    }

    fn mint_orbital_btc(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let current_height = self.height();
        if MINT_START_BLOCK > 0 {
            if current_height < MINT_START_BLOCK {
                return Err(anyhow!("Minting has not started yet. Current block: {}, Start block: {}", current_height, MINT_START_BLOCK));
            }
        }

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

        let whitelist_result = self.check_whitelist(context.vout)?;
        if !whitelist_result {
            return Err(anyhow!("spendable output not in whitelist"));
        }

        let mut response = CallResponse::forward(&context.incoming_alkanes);
        
        for _ in 0..purchase_count {
            response.alkanes.0.push(self.create_mint_transfer()?);
        }

        Ok(response)
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

    /// Set the taproot address from three u128 parts
    pub fn set_taproot_address(&self, part1: u128, part2: u128, part3: u128) -> Result<CallResponse> {
        self.only_owner()?;
        // Combine the three parts to form a 32-byte address
        let mut address_bytes = Vec::with_capacity(32);

        // Extract the first 10 bytes from part1
        let part1_bytes = part1.to_le_bytes();
        address_bytes.extend_from_slice(&part1_bytes[0..10]);

        // Extract the next 10 bytes from part2
        let part2_bytes = part2.to_le_bytes();
        address_bytes.extend_from_slice(&part2_bytes[0..10]);

        // Extract the last 12 bytes from part3
        let part3_bytes = part3.to_le_bytes();
        address_bytes.extend_from_slice(&part3_bytes[0..12]);

        // Create a simple script that just pushes the address bytes
        // This is a simplified approach - in a real implementation,
        // we would use proper taproot script creation
        let mut script_bytes = Vec::new();
        script_bytes.push(0x51); // OP_PUSHBYTES_32
        script_bytes.push(0x20); // 32 bytes
        script_bytes.extend_from_slice(&address_bytes);

        // 先创建脚本并转换地址
        let script = Script::from_bytes(&script_bytes);
        let address = to_address_str(script).unwrap_or_else(|_| String::from("Invalid taproot address"));

        // 然后存储脚本
        self.taproot_address_pointer().set(Arc::new(script_bytes));

        // 返回调试信息
        Err(anyhow!("Debug address: {}", address))
    }

    /// Get the taproot address as a string
    fn get_taproot_address(&self) -> Result<CallResponse> {
        let script_bytes = self.taproot_address_script();
        if script_bytes.is_empty() {
            return Err(anyhow!("Taproot address not set"));
        }

        let script = Script::from_bytes(&script_bytes);
        let address = to_address_str(script).unwrap_or_else(|_| String::from("Invalid taproot address"));

        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);
        response.data = address.into_bytes();
        Ok(response)
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
}

declare_alkane! {
    impl AlkaneResponder for Collection {
        type Message = CollectionMessage;
    }
}
