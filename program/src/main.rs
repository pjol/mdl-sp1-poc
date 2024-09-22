//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let n = sp1_zkvm::io::read::<u32>();
    let mut a: u32 = 0;
    let mut b: u32 = 1;
    let mut sum;
    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }

    sp1_zkvm::io::write(0, a.to_be_bytes().as_slice());
    sp1_zkvm::io::write(0, b.to_be_bytes().as_slice());
}
