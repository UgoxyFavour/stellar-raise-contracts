use soroban_sdk::{token, Address};

/// Centralizes transfer direction for contributor refunds.
///
/// @notice Transfers `amount` tokens from `contract_address` to `contributor`.
/// @dev    Keeping this in one place prevents parameter-order typos at call sites.
pub fn refund_single_transfer(
    token_client: &token::Client,
    contract_address: &Address,
    contributor: &Address,
    amount: i128,
) {
    token_client.transfer(contract_address, contributor, &amount);
}
