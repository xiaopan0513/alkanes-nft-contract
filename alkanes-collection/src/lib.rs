//! # Alkane Collection Contract
//!
//! This contract implements an NFT collection with the following features:
//! - Dynamic minting difficulty based on block statistics
//! - Premine mechanism for initial token distribution
//! - Block height based minting start control
//! - Lottery-based minting success rate
//! - SVG-based token generation

use metashrew_support::index_pointer::KeyValuePointer;
use metashrew_support::compat::to_arraybuffer_layout;
use metashrew_support::utils::consensus_decode;
use alkanes_runtime::{
    declare_alkane, message::MessageDispatch, storage::StoragePointer, token::Token,
    runtime::AlkaneResponder,auth::AuthenticatedResponder
};

use alkanes_support::{
    cellpack::Cellpack, id::AlkaneId,
    parcel::{AlkaneTransfer, AlkaneTransferParcel}, response::CallResponse,
};

use anyhow::{anyhow, Result};
use std::sync::Arc;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Transaction,Script,TxOut};
use crate::generation::svg_generator::SvgGenerator;
use protorune_support::network::{to_address_str};
mod generation;

/// Template ID for orbital NFT
const ORBITAL_TEMPLATE_ID: u128 = 888001;

const MERKER_TREE_FACTORY_ID: u128 = 888002;
/// Name of the NFT collection
const CONTRACT_NAME: &str = "Alkane Oyly";

/// Symbol of the NFT collection
const CONTRACT_SYMBOL: &str = "Oyly";

/// Maximum number of NFTs that can be minted
const MAX_MINTS: u128 = 9900;

/// Number of NFTs to be premined during contract initialization
/// This value can be set to 0 if no premine is needed
const PREMINE_MINTS: u128 = 100;

/// Initial difficulty for minting (5 = 20% success rate)
const INITIAL_DIFFICULTY: u128 = 5;

/// Minimum difficulty for minting (10 = 10% success rate)
const MIN_DIFFICULTY: u128 = 10;

/// Target number of mints per block for difficulty adjustment
const TARGET_MINTS_PER_BLOCK: u32 = 10;

/// Block height at which public minting begins
/// If set to 0, minting will be available immediately without block height restriction
const MINT_START_BLOCK: u64 = 251733;

const PAYMENT_ALKANEID :AlkaneId = AlkaneId{block:6,tx:1};

const MIN_PAYMENT_VALUE :u128 = 10000000;

const STAGE_LINE_HEIGHT :u64 = 251733;

const AUTH_TOKEN_UNITS :u128 = 100000000;

const MIN_BTC_PAYMENT_VALUE :u128 = 10000;

const MERKER_TREE_LENGTH: u128 = 16;
static MERKER_TREE_ROOT_VALUE: [u128; 16] = [0; 16];

/// Collection Contract Structure
/// This is the main contract structure that implements the NFT collection functionality
#[derive(Default)]
pub struct Collection(());

/// Implementation of AlkaneResponder trait for the collection
impl AlkaneResponder for Collection {}

impl AuthenticatedResponder for Collection {}


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

    /// Withdraw payment alkanes
    #[opcode(1003)]
    WithdrawPaymentAlkanes { count: u128 },

    #[opcode(1004)]
    DeployMerkleTree { count: u128, root: Vec<u128> },

    #[opcode(1005)]
    SetTaprootAddress { part1: u128, part2: u128, part3: u128 },
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
    /// This function:
    /// 1. Sets initial difficulty and block statistics
    /// 2. Initializes all necessary storage values
    ///
    /// # Returns
    /// * `Result<CallResponse>` - Success or failure of initialization
    fn initialize(&self) -> Result<CallResponse> {
        self.observe_initialization()?;

        // Initialize storage values
        self.set_difficulty(INITIAL_DIFFICULTY);
        self.set_current_block_mints(0);
        self.set_last_block_height(self.height());
        self.set_instances_count(0);
        self.set_auth_mint_count(0);  // Initialize auth mint count to 0

        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        // Collection token acts as auth token for contract minting without any limits
        if PREMINE_MINTS > 0 {
            response.alkanes.0.push(AlkaneTransfer {
                id: context.myself.clone(),
                value: 1u128,
            });
        }
        self.deploy_merkle_tree(MERKER_TREE_LENGTH, MERKER_TREE_ROOT_VALUE.to_vec())?;
        response.alkanes.0.push(self.deploy_auth_token(AUTH_TOKEN_UNITS).unwrap());

        Ok(response)
    }

    fn deploy_merkle_tree(&self, length: u128, root: Vec<u128>) -> Result<CallResponse> {
        self.only_owner()?;
        
        // 检查是否已经部署过
        let merkle_ptr = StoragePointer::from_keyword("/merker_tree");
        if !merkle_ptr.get().as_ref().is_empty() {
            return Err(anyhow!("Merkle tree already deployed"));
        }

        let mut inputs = vec![0x0, length];
        inputs.extend(root);
        let cellpack = Cellpack {
            target: AlkaneId {
                block: 6,
                tx: MERKER_TREE_FACTORY_ID,
            },
            inputs,
        };
        let sequence = self.sequence();
        let mut transfer =  AlkaneTransferParcel::default();
        let context = self.context()?;
        transfer.0.push(AlkaneTransfer{id:context.myself.clone(),value:MAX_MINTS});
        self.call(&cellpack, &transfer, self.fuel())?;
        let mut ptr = StoragePointer::from_keyword("/merker_tree");
        ptr.set(Arc::new(<AlkaneId as Into<Vec<u8>>>::into(AlkaneId {
            block: 2,
            tx: sequence,
        })));
        Ok(CallResponse::forward(&context.incoming_alkanes))
    }

    fn merkle_alkane(&self) -> Result<AlkaneId> {
        let pointer = StoragePointer::from_keyword("/merker_tree").get();
        Ok(pointer.as_ref().clone().try_into()?)
    }
    fn claim_merkle_tree(&self) -> Result<u128> {
        let merkle_alkane_id = self.merkle_alkane()?;
        let cellpack = Cellpack {
            target: merkle_alkane_id,
            inputs: vec![0x1],
        };

        let response = self.call(&cellpack, &AlkaneTransferParcel::default(), self.fuel())?;
        
        let context = self.context()?;
        let value = response.alkanes.0
            .iter()
            .find(|transfer| transfer.id == context.myself)
            .map(|transfer| transfer.value)
            .ok_or_else(|| anyhow!("No matching transfer found"))?;
        Ok(value)
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

    fn payment_alkanes_mint(&self) ->Result<CallResponse>{
        let context = self.context()?;
        let mut incoming_alkanes = context.incoming_alkanes.clone();
        
        // 找到 deposit_transfer 的索引
        let deposit_index = incoming_alkanes
            .0
            .iter()
            .position(|transfer| transfer.id == PAYMENT_ALKANEID)
            .ok_or_else(|| anyhow!("Deposit transfer not found"))?;

        // 获取并检查 deposit_transfer 的值
        let amount = incoming_alkanes.0[deposit_index].value;
        if amount < MIN_PAYMENT_VALUE {
            return Err(anyhow!("Payment amount {} below minimum {}", amount, MIN_PAYMENT_VALUE));
        }

        // 从 incoming_alkanes 中移除 deposit_transfer
        incoming_alkanes.0.remove(deposit_index);

        let mut response = CallResponse::forward(&incoming_alkanes);
        self.observe_mint()?;
        response.alkanes.0.push(self.create_mint_transfer()?);

        Ok(response)
    }

    fn withdraw_payment_alkanes(&self,count:u128) ->Result<CallResponse>{
        self.only_owner()?;
        
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);
        if self.balance(&context.myself, &PAYMENT_ALKANEID) < count {
            return Err(anyhow!("Insufficient balance"));
        }
        response.alkanes.0.push(AlkaneTransfer{id:context.myself.clone(),value:count});

        Ok(response)
    }

    /// Get the pointer to the taproot address
    pub fn taproot_address_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/taproot-address")
    }

    /// Get the taproot address script
    pub fn taproot_address_script(&self) -> Vec<u8> {
        self.taproot_address_pointer().get().as_ref().clone()
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
        script_bytes.extend_from_slice(&address_bytes);
        
        // Store the script
        self.taproot_address_pointer().set(Arc::new(script_bytes));
        Ok(CallResponse::forward(&self.context()?.incoming_alkanes))
    }

    /// Get the taproot address as a string
    pub fn taproot_address(&self) -> String {
        let script_bytes = self.taproot_address_script();
        if script_bytes.is_empty() {
            return String::from("Taproot address not set");
        }
        
        let script = Script::from_bytes(&script_bytes);
        to_address_str(script).unwrap_or_else(|_| String::from("Invalid taproot address"))
    }

    /// Compute the total output value sent to the taproot address
    fn compute_btc_output(&self, tx: &Transaction) -> u128 {
        let taproot_script = self.taproot_address_script();
        if taproot_script.is_empty() {
            return 0;
        }
        
        let total = tx.output.iter().fold(0, |r: u128, v: &TxOut| -> u128 {
            if v.script_pubkey.as_bytes().to_vec() == taproot_script {
                r + <u64 as Into<u128>>::into(v.value.to_sat())
            } else {
                r
            }
        });
        
        total
    }
    
    fn payment_btc_mint(&self) ->Result<CallResponse>{
        let context = self.context()?;

        let tx = consensus_decode::<Transaction>(&mut std::io::Cursor::new(self.transaction()))
            .map_err(|e| anyhow!("Failed to parse Bitcoin transaction: {}", e))?;
        let btc_amount = self.compute_btc_output(&tx);
        
        // Check if payment was provided
        if btc_amount < MIN_BTC_PAYMENT_VALUE {
            return Err(anyhow!("BTC payment amount {} below minimum {}", btc_amount, MIN_BTC_PAYMENT_VALUE));
        }

        let mut response = CallResponse::forward(&context.incoming_alkanes);
        self.observe_mint()?;
        response.alkanes.0.push(self.create_mint_transfer()?);

        Ok(response)
    }

    /// Public mint function for orbitals
    ///
    /// This function:
    /// 1. Checks if current block height has reached mint start block
    /// 2. Updates block statistics and adjusts difficulty
    /// 3. Calculates minting success based on difficulty
    /// 4. Creates new NFT if successful
    ///
    /// # Returns
    /// * `Result<CallResponse>` - Success or failure of minting operation
    fn mint_orbital(&self) -> Result<CallResponse> {
        if self.height() < STAGE_LINE_HEIGHT {
            return self.payment_alkanes_mint()
        }else{
            return self.payment_btc_mint()
        }
        

        
        // let mut parcel = context.incoming_alkanes.clone();
        // parcel.pay( AlkaneTransfer{id:PAYMENT_ALKANEID,value:MIN_PAYMENT_VALUE});
        // let mut response = CallResponse::forward(&parcel);

        // self.observe_mint()?;
        // response.alkanes.0.push(self.create_mint_transfer()?);

        // Ok(response)
    }

    /// Create a mint transfer
    ///
    /// # Returns
    /// * `Result<AlkaneTransfer>` - The transfer object or error
    fn create_mint_transfer(&self) -> Result<AlkaneTransfer> {
        let index = self.instances_count();

        if index >= self.max_mints() {
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

    /// Get storage pointer for difficulty
    ///
    /// # Returns
    /// * `StoragePointer` - Pointer to difficulty storage
    fn get_difficulty_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/difficulty")
    }

    /// Get current difficulty level
    ///
    /// Higher difficulty means lower success rate
    ///
    /// # Returns
    /// * `u128` - Current difficulty value
    fn get_difficulty(&self) -> u128 {
        let difficulty = self.get_difficulty_pointer().get_value::<u128>();
        if difficulty == 0 {
            INITIAL_DIFFICULTY // Initial 20% success rate
        } else {
            difficulty
        }
    }

    /// Set current difficulty level
    ///
    /// # Arguments
    /// * `difficulty` - New difficulty value
    fn set_difficulty(&self, difficulty: u128) {
        self.get_difficulty_pointer().set_value(difficulty);
    }

    /// Get storage pointer for last processed block height
    fn get_last_block_height_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/last_block_height")
    }

    /// Get storage pointer for current block mints
    fn get_current_block_mints_pointer(&self) -> StoragePointer {
        StoragePointer::from_keyword("/current_block_mints")
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

    /// Get last processed block height
    fn get_last_block_height(&self) -> u64 {
        self.get_last_block_height_pointer().get_value()
    }

    /// Set last processed block height
    fn set_last_block_height(&self, height: u64) {
        self.get_last_block_height_pointer().set_value(height);
    }

    /// Get current block mints
    fn get_current_block_mints(&self) -> u32 {
        self.get_current_block_mints_pointer().get_value()
    }

    /// Set current block mints
    fn set_current_block_mints(&self, mints: u32) {
        self.get_current_block_mints_pointer().set_value(mints);
    }

    /// Update block statistics and adjust difficulty for the next block
    ///
    /// This function:
    /// 1. Checks if we're in a new block
    /// 2. Adjusts difficulty based on previous block's mint count
    /// 3. Resets block counter
    /// 4. Updates last block height
    ///
    /// # Returns
    /// * `Result<()>` - Success or failure of update
    fn update_block_stats(&self) -> Result<()> {
        let current_height = self.height();
        let last_height = self.get_last_block_height();

        // If entering a new block, adjust the difficulty based on the number of mints in the previous block
        // Reset block counter and update difficulty
        // Use bitcoin_hashes SHA256 to hash the entire transaction data
        // Use the first 16 bytes of the hash result as a random value
        // Only record the number of mints on success
        if current_height != last_height {
            let block_mints = self.get_current_block_mints();
            let current_difficulty = self.get_difficulty();

            // Adjust the difficulty for the next block
            // Reset block counter and update difficulty
            let new_difficulty = if block_mints > TARGET_MINTS_PER_BLOCK {
                current_difficulty.saturating_add(1)
            } else if block_mints < TARGET_MINTS_PER_BLOCK {
                current_difficulty.saturating_sub(1).max(MIN_DIFFICULTY)
            } else {
                current_difficulty
            };

            // Reset block counter and update difficulty
            self.set_difficulty(new_difficulty);
            self.set_current_block_mints(0);
            self.set_last_block_height(current_height);
        }

        Ok(())
    }

    /// Calculate a random value from transaction data
    ///
    /// Uses SHA256 hash of transaction data to generate a random value
    /// Takes first 16 bytes of hash as random number
    ///
    /// # Returns
    /// * `u128` - Random value derived from transaction
    fn calculate_random_from_tx(&self) -> u128 {
        let tx_data = self.transaction();

        // Use bitcoin_hashes SHA256 to hash the entire transaction data
        // Use the first 16 bytes of the hash result as a random value
        let hash = sha256::Hash::hash(&tx_data);
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
    /// 4. Determines minting success based on difficulty
    ///
    /// # Returns
    /// * `Result<()>` - Success or failure of minting attempt
    fn observe_mint(&self) -> Result<()> {
        // Check if current block height has reached start block (if MINT_START_BLOCK > 0)
        if MINT_START_BLOCK > 0 {
            let current_height = self.height();
            if current_height < MINT_START_BLOCK {
                return Err(anyhow!("Minting has not started yet. Current block: {}, Start block: {}", current_height, MINT_START_BLOCK));
            }
        }

        // First update block statistics
        self.update_block_stats()?;

        let merkle_alkane_value = self.claim_merkle_tree()?;    
        if merkle_alkane_value != 1 {
            return Err(anyhow!("No in merkle tree"));
        }

        // Check if minting is successful using the current difficulty
        let random_value = self.calculate_random_from_tx();
        let difficulty = self.get_difficulty();

        let success = random_value % difficulty == 0;

        if success {
            // Only record the number of mints on success
            self.record_successful_mint()?;
            Ok(())
        } else {
            Err(anyhow!("The transaction was not matched in the lottery."))
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
        let total_supply = self.instances_count() * 100000000u128;
        response.data = total_supply.to_le_bytes().to_vec();

        Ok(response)
    }

    /// Get the total count of orbitals
    fn get_orbital_count(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = MAX_MINTS.to_le_bytes().to_vec();

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

    /// Record successful minting
    ///
    /// Increments the current block's mint counter
    ///
    /// # Returns
    /// * `Result<()>` - Success or failure of recording
    fn record_successful_mint(&self) -> Result<()> {
        let current_mints = self.get_current_block_mints();
        self.set_current_block_mints(current_mints + 1);
        Ok(())
    }
}

declare_alkane! {
    impl AlkaneResponder for Collection {
        type Message = CollectionMessage;
    }
}
