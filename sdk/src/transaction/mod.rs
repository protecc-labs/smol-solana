//! Atomically-committed sequences of instructions.
//!
//! While [`Instruction`]s are the basic unit of computation in Solana, they are
//! submitted by clients in [`Transaction`]s containing one or more
//! instructions, and signed by one or more [`Signer`]s. Solana executes the
//! instructions in a transaction in order, and only commits any changes if all
//! instructions terminate without producing an error or exception.
//!
//! Transactions do not directly contain their instructions but instead include
//! a [`Message`], a precompiled representation of a sequence of instructions.
//! `Message`'s constructors handle the complex task of reordering the
//! individual lists of accounts required by each instruction into a single flat
//! list of deduplicated accounts required by the Solana runtime. The
//! `Transaction` type has constructors that build the `Message` so that clients
//! don't need to interact with them directly.
//!
//! Prior to submission to the network, transactions must be signed by one or or
//! more keypairs, and this signing is typically performed by an abstract
//! [`Signer`], which may be a [`Keypair`] but may also be other types of
//! signers including remote wallets, such as Ledger devices, as represented by
//! the [`RemoteKeypair`] type in the [`solana-remote-wallet`] crate.
//!
//! [`Signer`]: crate::signer::Signer
//! [`Keypair`]: crate::signer::keypair::Keypair
//! [`solana-remote-wallet`]: https://docs.rs/solana-remote-wallet/latest/
//! [`RemoteKeypair`]: https://docs.rs/solana-remote-wallet/latest/solana_remote_wallet/remote_keypair/struct.RemoteKeypair.html
//!
//! Every transaction must be signed by a fee-paying account, the account from
//! which the cost of executing the transaction is withdrawn. Other required
//! signatures are determined by the requirements of the programs being executed
//! by each instruction, and are conventionally specified by that program's
//! documentation.
//!
//! When signing a transaction, a recent blockhash must be provided (which can
//! be retrieved with [`RpcClient::get_latest_blockhash`]). This allows
//! validators to drop old but unexecuted transactions; and to distinguish
//! between accidentally duplicated transactions and intentionally duplicated
//! transactions &mdash; any identical transactions will not be executed more
//! than once, so updating the blockhash between submitting otherwise identical
//! transactions makes them unique. If a client must sign a transaction long
//! before submitting it to the network, then it can use the _[durable
//! transaction nonce]_ mechanism instead of a recent blockhash to ensure unique
//! transactions.
//!
//! [`RpcClient::get_latest_blockhash`]: https://docs.rs/solana-rpc-client/latest/solana_rpc_client/rpc_client/struct.RpcClient.html#method.get_latest_blockhash
//! [durable transaction nonce]: https://docs.solanalabs.com/implemented-proposals/durable-tx-nonces
//!
//! # Examples
//!
//! This example uses the [`solana_rpc_client`] and [`anyhow`] crates.
//!
//! [`solana_rpc_client`]: https://docs.rs/solana-rpc-client
//! [`anyhow`]: https://docs.rs/anyhow
//!
//! ```
//! # use solana_sdk::example_mocks::solana_rpc_client;
//! use anyhow::Result;
//! use borsh::{BorshSerialize, BorshDeserialize};
//! use solana_rpc_client::rpc_client::RpcClient;
//! use solana_sdk::{
//!      instruction::Instruction,
//!      message::Message,
//!      pubkey::Pubkey,
//!      signature::{Keypair, Signer},
//!      transaction::Transaction,
//! };
//!
//! // A custom program instruction. This would typically be defined in
//! // another crate so it can be shared between the on-chain program and
//! // the client.
//! #[derive(BorshSerialize, BorshDeserialize)]
//! enum BankInstruction {
//!     Initialize,
//!     Deposit { lamports: u64 },
//!     Withdraw { lamports: u64 },
//! }
//!
//! fn send_initialize_tx(
//!     client: &RpcClient,
//!     program_id: Pubkey,
//!     payer: &Keypair
//! ) -> Result<()> {
//!
//!     let bank_instruction = BankInstruction::Initialize;
//!
//!     let instruction = Instruction::new_with_borsh(
//!         program_id,
//!         &bank_instruction,
//!         vec![],
//!     );
//!
//!     let blockhash = client.get_latest_blockhash()?;
//!     let mut tx = Transaction::new_signed_with_payer(
//!         &[instruction],
//!         Some(&payer.pubkey()),
//!         &[payer],
//!         blockhash,
//!     );
//!     client.send_and_confirm_transaction(&tx)?;
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # let program_id = Pubkey::new_unique();
//! # let payer = Keypair::new();
//! # send_initialize_tx(&client, program_id, &payer)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```

#![cfg(feature = "full")]

use {
    crate::{
        hash::Hash,
        instruction::{CompiledInstruction, Instruction},
        message::Message,
        nonce::NONCED_TX_MARKER_IX_INDEX,
        precompiles::verify_if_precompile,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        sanitize::{Sanitize, SanitizeError},
        short_vec,
        signature::{Signature, SignerError},
        signers::Signers,
        wasm_bindgen,
    },
    serde::Serialize,
    solana_program::{system_instruction::SystemInstruction, system_program},
    solana_sdk::feature_set,
    std::result,
};

mod error;
mod sanitized;
mod versioned;

pub use {error::*, sanitized::*, versioned::*};

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TransactionVerificationMode {
    HashOnly,
    HashAndVerifyPrecompiles,
    FullVerification,
}

pub type Result<T> = result::Result<T, TransactionError>;

/// An atomically-committed sequence of instructions.
///
/// While [`Instruction`]s are the basic unit of computation in Solana,
/// they are submitted by clients in [`Transaction`]s containing one or
/// more instructions, and signed by one or more [`Signer`]s.
///
/// [`Signer`]: crate::signer::Signer
///
/// See the [module documentation] for more details about transactions.
///
/// [module documentation]: self
///
/// Some constructors accept an optional `payer`, the account responsible for
/// paying the cost of executing a transaction. In most cases, callers should
/// specify the payer explicitly in these constructors. In some cases though,
/// the caller is not _required_ to specify the payer, but is still allowed to:
/// in the [`Message`] structure, the first account is always the fee-payer, so
/// if the caller has knowledge that the first account of the constructed
/// transaction's `Message` is both a signer and the expected fee-payer, then
/// redundantly specifying the fee-payer is not strictly required.
#[wasm_bindgen]
#[frozen_abi(digest = "FZtncnS1Xk8ghHfKiXE5oGiUbw2wJhmfXQuNgQR3K6Mc")]
#[derive(Debug, PartialEq, Default, Eq, Clone, Serialize, Deserialize, AbiExample)]
pub struct Transaction {
    /// A set of signatures of a serialized [`Message`], signed by the first
    /// keys of the `Message`'s [`account_keys`], where the number of signatures
    /// is equal to [`num_required_signatures`] of the `Message`'s
    /// [`MessageHeader`].
    ///
    /// [`account_keys`]: Message::account_keys
    /// [`MessageHeader`]: crate::message::MessageHeader
    /// [`num_required_signatures`]: crate::message::MessageHeader::num_required_signatures
    // NOTE: Serialization-related changes must be paired with the direct read at sigverify.
    #[wasm_bindgen(skip)]
    #[serde(with = "short_vec")]
    pub signatures: Vec<Signature>,

    /// The message to sign.
    #[wasm_bindgen(skip)]
    pub message: Message,
}

impl Sanitize for Transaction {
    fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        if self.message.header.num_required_signatures as usize > self.signatures.len() {
            return Err(SanitizeError::IndexOutOfBounds);
        }
        if self.signatures.len() > self.message.account_keys.len() {
            return Err(SanitizeError::IndexOutOfBounds);
        }
        self.message.sanitize()
    }
}

impl Transaction {
    /// Create an unsigned transaction from a [`Message`].
    ///
    /// # Examples
    ///
    /// This example uses the [`solana_rpc_client`] and [`anyhow`] crates.
    ///
    /// [`solana_rpc_client`]: https://docs.rs/solana-rpc-client
    /// [`anyhow`]: https://docs.rs/anyhow
    ///
    /// ```
    /// # use solana_sdk::example_mocks::solana_rpc_client;
    /// use anyhow::Result;
    /// use borsh::{BorshSerialize, BorshDeserialize};
    /// use solana_rpc_client::rpc_client::RpcClient;
    /// use solana_sdk::{
    ///      instruction::Instruction,
    ///      message::Message,
    ///      pubkey::Pubkey,
    ///      signature::{Keypair, Signer},
    ///      transaction::Transaction,
    /// };
    ///
    /// // A custom program instruction. This would typically be defined in
    /// // another crate so it can be shared between the on-chain program and
    /// // the client.
    /// #[derive(BorshSerialize, BorshDeserialize)]
    /// enum BankInstruction {
    ///     Initialize,
    ///     Deposit { lamports: u64 },
    ///     Withdraw { lamports: u64 },
    /// }
    ///
    /// fn send_initialize_tx(
    ///     client: &RpcClient,
    ///     program_id: Pubkey,
    ///     payer: &Keypair
    /// ) -> Result<()> {
    ///
    ///     let bank_instruction = BankInstruction::Initialize;
    ///
    ///     let instruction = Instruction::new_with_borsh(
    ///         program_id,
    ///         &bank_instruction,
    ///         vec![],
    ///     );
    ///
    ///     let message = Message::new(
    ///         &[instruction],
    ///         Some(&payer.pubkey()),
    ///     );
    ///
    ///     let mut tx = Transaction::new_unsigned(message);
    ///     let blockhash = client.get_latest_blockhash()?;
    ///     tx.sign(&[payer], blockhash);
    ///     client.send_and_confirm_transaction(&tx)?;
    ///
    ///     Ok(())
    /// }
    /// #
    /// # let client = RpcClient::new(String::new());
    /// # let program_id = Pubkey::new_unique();
    /// # let payer = Keypair::new();
    /// # send_initialize_tx(&client, program_id, &payer)?;
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new_unsigned(message: Message) -> Self {
        Self {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        }
    }

    /// Create a fully-signed transaction from a [`Message`].
    ///
    /// # Panics
    ///
    /// Panics when signing fails. See [`Transaction::try_sign`] and
    /// [`Transaction::try_partial_sign`] for a full description of failure
    /// scenarios.
    ///
    /// # Examples
    ///
    /// This example uses the [`solana_rpc_client`] and [`anyhow`] crates.
    ///
    /// [`solana_rpc_client`]: https://docs.rs/solana-rpc-client
    /// [`anyhow`]: https://docs.rs/anyhow
    ///
    /// ```
    /// # use solana_sdk::example_mocks::solana_rpc_client;
    /// use anyhow::Result;
    /// use borsh::{BorshSerialize, BorshDeserialize};
    /// use solana_rpc_client::rpc_client::RpcClient;
    /// use solana_sdk::{
    ///      instruction::Instruction,
    ///      message::Message,
    ///      pubkey::Pubkey,
    ///      signature::{Keypair, Signer},
    ///      transaction::Transaction,
    /// };
    ///
    /// // A custom program instruction. This would typically be defined in
    /// // another crate so it can be shared between the on-chain program and
    /// // the client.
    /// #[derive(BorshSerialize, BorshDeserialize)]
    /// enum BankInstruction {
    ///     Initialize,
    ///     Deposit { lamports: u64 },
    ///     Withdraw { lamports: u64 },
    /// }
    ///
    /// fn send_initialize_tx(
    ///     client: &RpcClient,
    ///     program_id: Pubkey,
    ///     payer: &Keypair
    /// ) -> Result<()> {
    ///
    ///     let bank_instruction = BankInstruction::Initialize;
    ///
    ///     let instruction = Instruction::new_with_borsh(
    ///         program_id,
    ///         &bank_instruction,
    ///         vec![],
    ///     );
    ///
    ///     let message = Message::new(
    ///         &[instruction],
    ///         Some(&payer.pubkey()),
    ///     );
    ///
    ///     let blockhash = client.get_latest_blockhash()?;
    ///     let mut tx = Transaction::new(&[payer], message, blockhash);
    ///     client.send_and_confirm_transaction(&tx)?;
    ///
    ///     Ok(())
    /// }
    /// #
    /// # let client = RpcClient::new(String::new());
    /// # let program_id = Pubkey::new_unique();
    /// # let payer = Keypair::new();
    /// # send_initialize_tx(&client, program_id, &payer)?;
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new<T: Signers + ?Sized>(
        from_keypairs: &T,
        message: Message,
        recent_blockhash: Hash,
    ) -> Transaction {
        let mut tx = Self::new_unsigned(message);
        tx.sign(from_keypairs, recent_blockhash);
        tx
    }

    /// Create an unsigned transaction from a list of [`Instruction`]s.
    ///
    /// `payer` is the account responsible for paying the cost of executing the
    /// transaction. It is typically provided, but is optional in some cases.
    /// See the [`Transaction`] docs for more.
    ///
    /// # Examples
    ///
    /// This example uses the [`solana_rpc_client`] and [`anyhow`] crates.
    ///
    /// [`solana_rpc_client`]: https://docs.rs/solana-rpc-client
    /// [`anyhow`]: https://docs.rs/anyhow
    ///
    /// ```
    /// # use solana_sdk::example_mocks::solana_rpc_client;
    /// use anyhow::Result;
    /// use borsh::{BorshSerialize, BorshDeserialize};
    /// use solana_rpc_client::rpc_client::RpcClient;
    /// use solana_sdk::{
    ///      instruction::Instruction,
    ///      message::Message,
    ///      pubkey::Pubkey,
    ///      signature::{Keypair, Signer},
    ///      transaction::Transaction,
    /// };
    ///
    /// // A custom program instruction. This would typically be defined in
    /// // another crate so it can be shared between the on-chain program and
    /// // the client.
    /// #[derive(BorshSerialize, BorshDeserialize)]
    /// enum BankInstruction {
    ///     Initialize,
    ///     Deposit { lamports: u64 },
    ///     Withdraw { lamports: u64 },
    /// }
    ///
    /// fn send_initialize_tx(
    ///     client: &RpcClient,
    ///     program_id: Pubkey,
    ///     payer: &Keypair
    /// ) -> Result<()> {
    ///
    ///     let bank_instruction = BankInstruction::Initialize;
    ///
    ///     let instruction = Instruction::new_with_borsh(
    ///         program_id,
    ///         &bank_instruction,
    ///         vec![],
    ///     );
    ///
    ///     let mut tx = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    ///     let blockhash = client.get_latest_blockhash()?;
    ///     tx.sign(&[payer], blockhash);
    ///     client.send_and_confirm_transaction(&tx)?;
    ///
    ///     Ok(())
    /// }
    /// #
    /// # let client = RpcClient::new(String::new());
    /// # let program_id = Pubkey::new_unique();
    /// # let payer = Keypair::new();
    /// # send_initialize_tx(&client, program_id, &payer)?;
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new_with_payer(instructions: &[Instruction], payer: Option<&Pubkey>) -> Self {
        let message = Message::new(instructions, payer);
        Self::new_unsigned(message)
    }

    /// Create a fully-signed transaction from a list of [`Instruction`]s.
    ///
    /// `payer` is the account responsible for paying the cost of executing the
    /// transaction. It is typically provided, but is optional in some cases.
    /// See the [`Transaction`] docs for more.
    ///
    /// # Panics
    ///
    /// Panics when signing fails. See [`Transaction::try_sign`] and
    /// [`Transaction::try_partial_sign`] for a full description of failure
    /// scenarios.
    ///
    /// # Examples
    ///
    /// This example uses the [`solana_rpc_client`] and [`anyhow`] crates.
    ///
    /// [`solana_rpc_client`]: https://docs.rs/solana-rpc-client
    /// [`anyhow`]: https://docs.rs/anyhow
    ///
    /// ```
    /// # use solana_sdk::example_mocks::solana_rpc_client;
    /// use anyhow::Result;
    /// use borsh::{BorshSerialize, BorshDeserialize};
    /// use solana_rpc_client::rpc_client::RpcClient;
    /// use solana_sdk::{
    ///      instruction::Instruction,
    ///      message::Message,
    ///      pubkey::Pubkey,
    ///      signature::{Keypair, Signer},
    ///      transaction::Transaction,
    /// };
    ///
    /// // A custom program instruction. This would typically be defined in
    /// // another crate so it can be shared between the on-chain program and
    /// // the client.
    /// #[derive(BorshSerialize, BorshDeserialize)]
    /// enum BankInstruction {
    ///     Initialize,
    ///     Deposit { lamports: u64 },
    ///     Withdraw { lamports: u64 },
    /// }
    ///
    /// fn send_initialize_tx(
    ///     client: &RpcClient,
    ///     program_id: Pubkey,
    ///     payer: &Keypair
    /// ) -> Result<()> {
    ///
    ///     let bank_instruction = BankInstruction::Initialize;
    ///
    ///     let instruction = Instruction::new_with_borsh(
    ///         program_id,
    ///         &bank_instruction,
    ///         vec![],
    ///     );
    ///
    ///     let blockhash = client.get_latest_blockhash()?;
    ///     let mut tx = Transaction::new_signed_with_payer(
    ///         &[instruction],
    ///         Some(&payer.pubkey()),
    ///         &[payer],
    ///         blockhash,
    ///     );
    ///     client.send_and_confirm_transaction(&tx)?;
    ///
    ///     Ok(())
    /// }
    /// #
    /// # let client = RpcClient::new(String::new());
    /// # let program_id = Pubkey::new_unique();
    /// # let payer = Keypair::new();
    /// # send_initialize_tx(&client, program_id, &payer)?;
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn new_signed_with_payer<T: Signers + ?Sized>(
        instructions: &[Instruction],
        payer: Option<&Pubkey>,
        signing_keypairs: &T,
        recent_blockhash: Hash,
    ) -> Self {
        let message = Message::new(instructions, payer);
        Self::new(signing_keypairs, message, recent_blockhash)
    }

    /// Create a fully-signed transaction from pre-compiled instructions.
    ///
    /// # Arguments
    ///
    /// * `from_keypairs` - The keys used to sign the transaction.
    /// * `keys` - The keys for the transaction.  These are the program state
    ///    instances or lamport recipient keys.
    /// * `recent_blockhash` - The PoH hash.
    /// * `program_ids` - The keys that identify programs used in the `instruction` vector.
    /// * `instructions` - Instructions that will be executed atomically.
    ///
    /// # Panics
    ///
    /// Panics when signing fails. See [`Transaction::try_sign`] and for a full
    /// description of failure conditions.
    pub fn new_with_compiled_instructions<T: Signers + ?Sized>(
        from_keypairs: &T,
        keys: &[Pubkey],
        recent_blockhash: Hash,
        program_ids: Vec<Pubkey>,
        instructions: Vec<CompiledInstruction>,
    ) -> Self {
        let mut account_keys = from_keypairs.pubkeys();
        let from_keypairs_len = account_keys.len();
        account_keys.extend_from_slice(keys);
        account_keys.extend(&program_ids);
        let message = Message::new_with_compiled_instructions(
            from_keypairs_len as u8,
            0,
            program_ids.len() as u8,
            account_keys,
            Hash::default(),
            instructions,
        );
        Transaction::new(from_keypairs, message, recent_blockhash)
    }

    /// Get the data for an instruction at the given index.
    ///
    /// The `instruction_index` corresponds to the [`instructions`] vector of
    /// the `Transaction`'s [`Message`] value.
    ///
    /// [`instructions`]: Message::instructions
    ///
    /// # Panics
    ///
    /// Panics if `instruction_index` is greater than or equal to the number of
    /// instructions in the transaction.
    pub fn data(&self, instruction_index: usize) -> &[u8] {
        &self.message.instructions[instruction_index].data
    }

    fn key_index(&self, instruction_index: usize, accounts_index: usize) -> Option<usize> {
        self.message
            .instructions
            .get(instruction_index)
            .and_then(|instruction| instruction.accounts.get(accounts_index))
            .map(|&account_keys_index| account_keys_index as usize)
    }

    /// Get the `Pubkey` of an account required by one of the instructions in
    /// the transaction.
    ///
    /// The `instruction_index` corresponds to the [`instructions`] vector of
    /// the `Transaction`'s [`Message`] value; and the `account_index` to the
    /// [`accounts`] vector of the message's [`CompiledInstruction`]s.
    ///
    /// [`instructions`]: Message::instructions
    /// [`accounts`]: CompiledInstruction::accounts
    /// [`CompiledInstruction`]: CompiledInstruction
    ///
    /// Returns `None` if `instruction_index` is greater than or equal to the
    /// number of instructions in the transaction; or if `accounts_index` is
    /// greater than or equal to the number of accounts in the instruction.
    pub fn key(&self, instruction_index: usize, accounts_index: usize) -> Option<&Pubkey> {
        self.key_index(instruction_index, accounts_index)
            .and_then(|account_keys_index| self.message.account_keys.get(account_keys_index))
    }

    /// Get the `Pubkey` of a signing account required by one of the
    /// instructions in the transaction.
    ///
    /// The transaction does not need to be signed for this function to return a
    /// signing account's pubkey.
    ///
    /// Returns `None` if the indexed account is not required to sign the
    /// transaction. Returns `None` if the [`signatures`] field does not contain
    /// enough elements to hold a signature for the indexed account (this should
    /// only be possible if `Transaction` has been manually constructed).
    ///
    /// [`signatures`]: Transaction::signatures
    ///
    /// Returns `None` if `instruction_index` is greater than or equal to the
    /// number of instructions in the transaction; or if `accounts_index` is
    /// greater than or equal to the number of accounts in the instruction.
    pub fn signer_key(&self, instruction_index: usize, accounts_index: usize) -> Option<&Pubkey> {
        match self.key_index(instruction_index, accounts_index) {
            None => None,
            Some(signature_index) => {
                if signature_index >= self.signatures.len() {
                    return None;
                }
                self.message.account_keys.get(signature_index)
            }
        }
    }

    /// Return the message containing all data that should be signed.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Return the serialized message data to sign.
    pub fn message_data(&self) -> Vec<u8> {
        self.message().serialize()
    }

    /// Sign the transaction.
    ///
    /// This method fully signs a transaction with all required signers, which
    /// must be present in the `keypairs` slice. To sign with only some of the
    /// required signers, use [`Transaction::partial_sign`].
    ///
    /// If `recent_blockhash` is different than recorded in the transaction message's
    /// [`recent_blockhash`] field, then the message's `recent_blockhash` will be updated
    /// to the provided `recent_blockhash`, and any prior signatures will be cleared.
    ///
    /// [`recent_blockhash`]: Message::recent_blockhash
    ///
    /// # Panics
    ///
    /// Panics when signing fails. Use [`Transaction::try_sign`] to handle the
    /// error. See the documentation for [`Transaction::try_sign`] for a full description of
    /// failure conditions.
    ///
    /// # Examples
    ///
    /// This example uses the [`solana_rpc_client`] and [`anyhow`] crates.
    ///
    /// [`solana_rpc_client`]: https://docs.rs/solana-rpc-client
    /// [`anyhow`]: https://docs.rs/anyhow
    ///
    /// ```
    /// # use solana_sdk::example_mocks::solana_rpc_client;
    /// use anyhow::Result;
    /// use borsh::{BorshSerialize, BorshDeserialize};
    /// use solana_rpc_client::rpc_client::RpcClient;
    /// use solana_sdk::{
    ///      instruction::Instruction,
    ///      message::Message,
    ///      pubkey::Pubkey,
    ///      signature::{Keypair, Signer},
    ///      transaction::Transaction,
    /// };
    ///
    /// // A custom program instruction. This would typically be defined in
    /// // another crate so it can be shared between the on-chain program and
    /// // the client.
    /// #[derive(BorshSerialize, BorshDeserialize)]
    /// enum BankInstruction {
    ///     Initialize,
    ///     Deposit { lamports: u64 },
    ///     Withdraw { lamports: u64 },
    /// }
    ///
    /// fn send_initialize_tx(
    ///     client: &RpcClient,
    ///     program_id: Pubkey,
    ///     payer: &Keypair
    /// ) -> Result<()> {
    ///
    ///     let bank_instruction = BankInstruction::Initialize;
    ///
    ///     let instruction = Instruction::new_with_borsh(
    ///         program_id,
    ///         &bank_instruction,
    ///         vec![],
    ///     );
    ///
    ///     let mut tx = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    ///     let blockhash = client.get_latest_blockhash()?;
    ///     tx.sign(&[payer], blockhash);
    ///     client.send_and_confirm_transaction(&tx)?;
    ///
    ///     Ok(())
    /// }
    /// #
    /// # let client = RpcClient::new(String::new());
    /// # let program_id = Pubkey::new_unique();
    /// # let payer = Keypair::new();
    /// # send_initialize_tx(&client, program_id, &payer)?;
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn sign<T: Signers + ?Sized>(&mut self, keypairs: &T, recent_blockhash: Hash) {
        if let Err(e) = self.try_sign(keypairs, recent_blockhash) {
            panic!("Transaction::sign failed with error {e:?}");
        }
    }

    /// Sign the transaction with a subset of required keys.
    ///
    /// Unlike [`Transaction::sign`], this method does not require all keypairs
    /// to be provided, allowing a transaction to be signed in multiple steps.
    ///
    /// It is permitted to sign a transaction with the same keypair multiple
    /// times.
    ///
    /// If `recent_blockhash` is different than recorded in the transaction message's
    /// [`recent_blockhash`] field, then the message's `recent_blockhash` will be updated
    /// to the provided `recent_blockhash`, and any prior signatures will be cleared.
    ///
    /// [`recent_blockhash`]: Message::recent_blockhash
    ///
    /// # Panics
    ///
    /// Panics when signing fails. Use [`Transaction::try_partial_sign`] to
    /// handle the error. See the documentation for
    /// [`Transaction::try_partial_sign`] for a full description of failure
    /// conditions.
    pub fn partial_sign<T: Signers + ?Sized>(&mut self, keypairs: &T, recent_blockhash: Hash) {
        if let Err(e) = self.try_partial_sign(keypairs, recent_blockhash) {
            panic!("Transaction::partial_sign failed with error {e:?}");
        }
    }

    /// Sign the transaction with a subset of required keys.
    ///
    /// This places each of the signatures created from `keypairs` in the
    /// corresponding position, as specified in the `positions` vector, in the
    /// transactions [`signatures`] field. It does not verify that the signature
    /// positions are correct.
    ///
    /// [`signatures`]: Transaction::signatures
    ///
    /// # Panics
    ///
    /// Panics if signing fails. Use [`Transaction::try_partial_sign_unchecked`]
    /// to handle the error.
    pub fn partial_sign_unchecked<T: Signers + ?Sized>(
        &mut self,
        keypairs: &T,
        positions: Vec<usize>,
        recent_blockhash: Hash,
    ) {
        if let Err(e) = self.try_partial_sign_unchecked(keypairs, positions, recent_blockhash) {
            panic!("Transaction::partial_sign_unchecked failed with error {e:?}");
        }
    }

    /// Sign the transaction, returning any errors.
    ///
    /// This method fully signs a transaction with all required signers, which
    /// must be present in the `keypairs` slice. To sign with only some of the
    /// required signers, use [`Transaction::try_partial_sign`].
    ///
    /// If `recent_blockhash` is different than recorded in the transaction message's
    /// [`recent_blockhash`] field, then the message's `recent_blockhash` will be updated
    /// to the provided `recent_blockhash`, and any prior signatures will be cleared.
    ///
    /// [`recent_blockhash`]: Message::recent_blockhash
    ///
    /// # Errors
    ///
    /// Signing will fail if some required signers are not provided in
    /// `keypairs`; or, if the transaction has previously been partially signed,
    /// some of the remaining required signers are not provided in `keypairs`.
    /// In other words, the transaction must be fully signed as a result of
    /// calling this function. The error is [`SignerError::NotEnoughSigners`].
    ///
    /// Signing will fail for any of the reasons described in the documentation
    /// for [`Transaction::try_partial_sign`].
    ///
    /// # Examples
    ///
    /// This example uses the [`solana_rpc_client`] and [`anyhow`] crates.
    ///
    /// [`solana_rpc_client`]: https://docs.rs/solana-rpc-client
    /// [`anyhow`]: https://docs.rs/anyhow
    ///
    /// ```
    /// # use solana_sdk::example_mocks::solana_rpc_client;
    /// use anyhow::Result;
    /// use borsh::{BorshSerialize, BorshDeserialize};
    /// use solana_rpc_client::rpc_client::RpcClient;
    /// use solana_sdk::{
    ///      instruction::Instruction,
    ///      message::Message,
    ///      pubkey::Pubkey,
    ///      signature::{Keypair, Signer},
    ///      transaction::Transaction,
    /// };
    ///
    /// // A custom program instruction. This would typically be defined in
    /// // another crate so it can be shared between the on-chain program and
    /// // the client.
    /// #[derive(BorshSerialize, BorshDeserialize)]
    /// enum BankInstruction {
    ///     Initialize,
    ///     Deposit { lamports: u64 },
    ///     Withdraw { lamports: u64 },
    /// }
    ///
    /// fn send_initialize_tx(
    ///     client: &RpcClient,
    ///     program_id: Pubkey,
    ///     payer: &Keypair
    /// ) -> Result<()> {
    ///
    ///     let bank_instruction = BankInstruction::Initialize;
    ///
    ///     let instruction = Instruction::new_with_borsh(
    ///         program_id,
    ///         &bank_instruction,
    ///         vec![],
    ///     );
    ///
    ///     let mut tx = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    ///     let blockhash = client.get_latest_blockhash()?;
    ///     tx.try_sign(&[payer], blockhash)?;
    ///     client.send_and_confirm_transaction(&tx)?;
    ///
    ///     Ok(())
    /// }
    /// #
    /// # let client = RpcClient::new(String::new());
    /// # let program_id = Pubkey::new_unique();
    /// # let payer = Keypair::new();
    /// # send_initialize_tx(&client, program_id, &payer)?;
    /// #
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn try_sign<T: Signers + ?Sized>(
        &mut self,
        keypairs: &T,
        recent_blockhash: Hash,
    ) -> result::Result<(), SignerError> {
        self.try_partial_sign(keypairs, recent_blockhash)?;

        if !self.is_signed() {
            Err(SignerError::NotEnoughSigners)
        } else {
            Ok(())
        }
    }

    /// Sign the transaction with a subset of required keys, returning any errors.
    ///
    /// Unlike [`Transaction::try_sign`], this method does not require all
    /// keypairs to be provided, allowing a transaction to be signed in multiple
    /// steps.
    ///
    /// It is permitted to sign a transaction with the same keypair multiple
    /// times.
    ///
    /// If `recent_blockhash` is different than recorded in the transaction message's
    /// [`recent_blockhash`] field, then the message's `recent_blockhash` will be updated
    /// to the provided `recent_blockhash`, and any prior signatures will be cleared.
    ///
    /// [`recent_blockhash`]: Message::recent_blockhash
    ///
    /// # Errors
    ///
    /// Signing will fail if
    ///
    /// - The transaction's [`Message`] is malformed such that the number of
    ///   required signatures recorded in its header
    ///   ([`num_required_signatures`]) is greater than the length of its
    ///   account keys ([`account_keys`]). The error is
    ///   [`SignerError::TransactionError`] where the interior
    ///   [`TransactionError`] is [`TransactionError::InvalidAccountIndex`].
    /// - Any of the provided signers in `keypairs` is not a required signer of
    ///   the message. The error is [`SignerError::KeypairPubkeyMismatch`].
    /// - Any of the signers is a [`Presigner`], and its provided signature is
    ///   incorrect. The error is [`SignerError::PresignerError`] where the
    ///   interior [`PresignerError`] is
    ///   [`PresignerError::VerificationFailure`].
    /// - The signer is a [`RemoteKeypair`] and
    ///   - It does not understand the input provided ([`SignerError::InvalidInput`]).
    ///   - The device cannot be found ([`SignerError::NoDeviceFound`]).
    ///   - The user cancels the signing ([`SignerError::UserCancel`]).
    ///   - An error was encountered connecting ([`SignerError::Connection`]).
    ///   - Some device-specific protocol error occurs ([`SignerError::Protocol`]).
    ///   - Some other error occurs ([`SignerError::Custom`]).
    ///
    /// See the documentation for the [`solana-remote-wallet`] crate for details
    /// on the operation of [`RemoteKeypair`] signers.
    ///
    /// [`num_required_signatures`]: crate::message::MessageHeader::num_required_signatures
    /// [`account_keys`]: Message::account_keys
    /// [`Presigner`]: crate::signer::presigner::Presigner
    /// [`PresignerError`]: crate::signer::presigner::PresignerError
    /// [`PresignerError::VerificationFailure`]: crate::signer::presigner::PresignerError::VerificationFailure
    /// [`solana-remote-wallet`]: https://docs.rs/solana-remote-wallet/latest/
    /// [`RemoteKeypair`]: https://docs.rs/solana-remote-wallet/latest/solana_remote_wallet/remote_keypair/struct.RemoteKeypair.html
    pub fn try_partial_sign<T: Signers + ?Sized>(
        &mut self,
        keypairs: &T,
        recent_blockhash: Hash,
    ) -> result::Result<(), SignerError> {
        let positions = self.get_signing_keypair_positions(&keypairs.pubkeys())?;
        if positions.iter().any(|pos| pos.is_none()) {
            return Err(SignerError::KeypairPubkeyMismatch);
        }
        let positions: Vec<usize> = positions.iter().map(|pos| pos.unwrap()).collect();
        self.try_partial_sign_unchecked(keypairs, positions, recent_blockhash)
    }

    /// Sign the transaction with a subset of required keys, returning any
    /// errors.
    ///
    /// This places each of the signatures created from `keypairs` in the
    /// corresponding position, as specified in the `positions` vector, in the
    /// transactions [`signatures`] field. It does not verify that the signature
    /// positions are correct.
    ///
    /// [`signatures`]: Transaction::signatures
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn try_partial_sign_unchecked<T: Signers + ?Sized>(
        &mut self,
        keypairs: &T,
        positions: Vec<usize>,
        recent_blockhash: Hash,
    ) -> result::Result<(), SignerError> {
        // if you change the blockhash, you're re-signing...
        if recent_blockhash != self.message.recent_blockhash {
            self.message.recent_blockhash = recent_blockhash;
            self.signatures
                .iter_mut()
                .for_each(|signature| *signature = Signature::default());
        }

        let signatures = keypairs.try_sign_message(&self.message_data())?;
        for i in 0..positions.len() {
            self.signatures[positions[i]] = signatures[i];
        }
        Ok(())
    }

    /// Returns a signature that is not valid for signing this transaction.
    pub fn get_invalid_signature() -> Signature {
        Signature::default()
    }

    /// Verifies that all signers have signed the message.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::SignatureFailure`] on error.
    pub fn verify(&self) -> Result<()> {
        let message_bytes = self.message_data();
        if !self
            ._verify_with_results(&message_bytes)
            .iter()
            .all(|verify_result| *verify_result)
        {
            Err(TransactionError::SignatureFailure)
        } else {
            Ok(())
        }
    }

    /// Verify the transaction and hash its message.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError::SignatureFailure`] on error.
    pub fn verify_and_hash_message(&self) -> Result<Hash> {
        let message_bytes = self.message_data();
        if !self
            ._verify_with_results(&message_bytes)
            .iter()
            .all(|verify_result| *verify_result)
        {
            Err(TransactionError::SignatureFailure)
        } else {
            Ok(Message::hash_raw_message(&message_bytes))
        }
    }

    /// Verifies that all signers have signed the message.
    ///
    /// Returns a vector with the length of required signatures, where each
    /// element is either `true` if that signer has signed, or `false` if not.
    pub fn verify_with_results(&self) -> Vec<bool> {
        self._verify_with_results(&self.message_data())
    }

    pub(crate) fn _verify_with_results(&self, message_bytes: &[u8]) -> Vec<bool> {
        self.signatures
            .iter()
            .zip(&self.message.account_keys)
            .map(|(signature, pubkey)| signature.verify(pubkey.as_ref(), message_bytes))
            .collect()
    }

    /// Verify the precompiled programs in this transaction.
    pub fn verify_precompiles(&self, feature_set: &feature_set::FeatureSet) -> Result<()> {
        for instruction in &self.message().instructions {
            // The Transaction may not be sanitized at this point
            if instruction.program_id_index as usize >= self.message().account_keys.len() {
                return Err(TransactionError::AccountNotFound);
            }
            let program_id = &self.message().account_keys[instruction.program_id_index as usize];

            verify_if_precompile(
                program_id,
                instruction,
                &self.message().instructions,
                feature_set,
            )
            .map_err(|_| TransactionError::InvalidAccountIndex)?;
        }
        Ok(())
    }

    /// Get the positions of the pubkeys in `account_keys` associated with signing keypairs.
    ///
    /// [`account_keys`]: Message::account_keys
    pub fn get_signing_keypair_positions(&self, pubkeys: &[Pubkey]) -> Result<Vec<Option<usize>>> {
        if self.message.account_keys.len() < self.message.header.num_required_signatures as usize {
            return Err(TransactionError::InvalidAccountIndex);
        }
        let signed_keys =
            &self.message.account_keys[0..self.message.header.num_required_signatures as usize];

        Ok(pubkeys
            .iter()
            .map(|pubkey| signed_keys.iter().position(|x| x == pubkey))
            .collect())
    }

    /// Replace all the signatures and pubkeys.
    pub fn replace_signatures(&mut self, signers: &[(Pubkey, Signature)]) -> Result<()> {
        let num_required_signatures = self.message.header.num_required_signatures as usize;
        if signers.len() != num_required_signatures
            || self.signatures.len() != num_required_signatures
            || self.message.account_keys.len() < num_required_signatures
        {
            return Err(TransactionError::InvalidAccountIndex);
        }

        signers
            .iter()
            .enumerate()
            .for_each(|(i, (pubkey, signature))| {
                self.signatures[i] = *signature;
                self.message.account_keys[i] = *pubkey;
            });

        self.verify()
    }

    pub fn is_signed(&self) -> bool {
        self.signatures
            .iter()
            .all(|signature| *signature != Signature::default())
    }
}

pub fn uses_durable_nonce(tx: &Transaction) -> Option<&CompiledInstruction> {
    let message = tx.message();
    message
        .instructions
        .get(NONCED_TX_MARKER_IX_INDEX as usize)
        .filter(|instruction| {
            // Is system program
            matches!(
                message.account_keys.get(instruction.program_id_index as usize),
                Some(program_id) if system_program::check_id(program_id)
            )
            // Is a nonce advance instruction
            && matches!(
                limited_deserialize(&instruction.data),
                Ok(SystemInstruction::AdvanceNonceAccount)
            )
            // Nonce account is writable
            && matches!(
                instruction.accounts.first(),
                Some(index) if message.is_writable(*index as usize)
            )
        })
}

#[deprecated]
pub fn get_nonce_pubkey_from_instruction<'a>(
    ix: &CompiledInstruction,
    tx: &'a Transaction,
) -> Option<&'a Pubkey> {
    ix.accounts.first().and_then(|idx| {
        let idx = *idx as usize;
        tx.message().account_keys.get(idx)
    })
}
