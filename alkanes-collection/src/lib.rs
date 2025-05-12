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
use bitcoin::hashes::{sha256, Hash};
use crate::generation::svg_generator::SvgGenerator;

mod generation;

/// Template ID for orbital NFT
const ORBITAL_TEMPLATE_ID: u128 = 896420;

/// Name of the NFT collection
const CONTRACT_NAME: &str = "Oyly";

/// Symbol of the NFT collection
const CONTRACT_SYMBOL: &str = "Oyly";

/// Maximum number of NFTs that can be minted
const MAX_MINTS: u128 = 9900;

/// Number of NFTs to be premined during contract initialization
/// This value can be set to 0 if no premine is needed
const PREMINE_MINTS: u128 = 100;

/// Block height at which public minting begins
/// If set to 0, minting will be available immediately without block height restriction
const MINT_START_BLOCK: u64 = 896420;

/// Success rate (percentage), e.g. 50 means 50%
const SUCCESS_RATE: u128 = 35;

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
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

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

        // Check if PREMINE_MINTS is greater than 0
        if PREMINE_MINTS == 0 {
            return Err(anyhow!("Premine minting is not enabled (PREMINE_MINTS is 0)"));
        }

        // Check if the requested mint count plus current auth mint count doesn't exceed PREMINE_MINTS
        let current_auth_mints = self.get_auth_mint_count();
        if current_auth_mints + count > PREMINE_MINTS {
            return Err(anyhow!("Requested mint count {} plus current auth mints {} would exceed premine limit of {}", 
                count, current_auth_mints, PREMINE_MINTS));
        }

        let mut minted_orbitals = Vec::new();

        // Mint the specified number of orbitals
        for _ in 0..count {
            minted_orbitals.push(self.create_mint_transfer()?);
        }

        // Update the auth mint count
        self.set_auth_mint_count(current_auth_mints + count);

        response.alkanes.0.extend(minted_orbitals);

        Ok(response)
    }

    /// Public mint function for orbitals
    ///
    /// # Returns
    /// * `Result<CallResponse>` - Success or failure of minting operation
    fn mint_orbital(&self) -> Result<CallResponse> {
        let context = self.context()?;

        let mut response = CallResponse::forward(&context.incoming_alkanes);

        self.observe_mint()?;
        response.alkanes.0.push(self.create_mint_transfer()?);

        Ok(response)
    }

    /// Create a mint transfer
    ///
    /// # Returns
    /// * `Result<AlkaneTransfer>` - The transfer object or error
    fn create_mint_transfer(&self) -> Result<AlkaneTransfer> {
        let index = self.instances_count();

        if index >= (self.max_mints() + PREMINE_MINTS) {
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

    /// Calculate a random value from transaction data
    ///
    /// Uses SHA256 hash of transaction data and block height to generate a random value
    /// Takes first 16 bytes of hash as random number
    ///
    /// # Arguments
    /// * `height` - Current block height
    ///
    /// # Returns
    /// * `u128` - Random value derived from transaction and block height
    fn calculate_random_from_tx(&self, height: u64) -> u128 {
        let tx_data = self.transaction();
        let height_bytes = height.to_le_bytes();

        // Combine transaction data with block height
        let mut combined_data = Vec::with_capacity(tx_data.len() + height_bytes.len());
        combined_data.extend_from_slice(&tx_data);
        combined_data.extend_from_slice(&height_bytes);

        // Use bitcoin_hashes SHA256 to hash the combined data
        let hash = sha256::Hash::hash(&combined_data);
        let result = hash.to_byte_array();

        // Use the first 16 bytes of the hash result as a random value
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&result[..16]);
        u128::from_le_bytes(bytes)
    }

    /// Check minting restrictions and process attempt
    ///
    /// This function:
    /// 1. Verifies block height requirements (if MINT_START_BLOCK > 0)
    /// 2. Updates block statistics
    /// 3. Calculates random value from transaction
    /// 4. Determines minting success based on SUCCESS_RATE percentage
    ///
    /// # Returns
    /// * `Result<()>` - Success or failure of minting attempt
    fn observe_mint(&self) -> Result<()> {
        // Check if current block height has reached start block (if MINT_START_BLOCK > 0)
        let current_height = self.height();
        if MINT_START_BLOCK > 0 {
            if current_height < MINT_START_BLOCK {
                return Err(anyhow!("Minting has not started yet. Current block: {}, Start block: {}", current_height, MINT_START_BLOCK));
            }
        }

        // Determine minting success based on SUCCESS_RATE percentage
        let random_value = self.calculate_random_from_tx(current_height);
        let success = (random_value % 100) < SUCCESS_RATE;
        if success {
            Ok(())
        } else {
            Err(anyhow!("The transaction {} was not matched.", random_value))
        }
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
}

declare_alkane! {
    impl AlkaneResponder for Collection {
        type Message = CollectionMessage;
    }
}
