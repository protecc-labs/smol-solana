//! Solana Rust-based SBF program utility functions and types

#![allow(clippy::arithmetic_side_effects)]

extern crate solana_program;
use solana_program::{log::sol_log_64, msg};

pub fn many_args(
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
    arg7: u64,
    arg8: u64,
    arg9: u64,
) -> u64 {
    msg!("Another package - many_args");
    sol_log_64(arg1, arg2, arg3, arg4, arg5);
    sol_log_64(arg6, arg7, arg8, arg9, 0);
    arg1 + arg2 + arg3 + arg4 + arg5 + arg6 + arg7 + arg8 + arg9
}

#[derive(Debug, PartialEq)]
pub struct Ret {
    pub group1: u128,
    pub group2: u128,
    pub group3: u128,
}

pub fn many_args_sret(
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
    arg7: u64,
    arg8: u64,
    arg9: u64,
) -> Ret {
    msg!("Another package - many_args_sret");
    sol_log_64(arg1, arg2, arg3, arg4, arg5);
    sol_log_64(arg6, arg7, arg8, arg9, 0);
    Ret {
        group1: u128::from(arg1) + u128::from(arg2) + u128::from(arg3),
        group2: u128::from(arg4) + u128::from(arg5) + u128::from(arg6),
        group3: u128::from(arg7) + u128::from(arg8) + u128::from(arg9),
    }
}
