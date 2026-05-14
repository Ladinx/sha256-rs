mod sha256_standalone;
mod file_hasher;

use std::env;

use crate::file_hasher::hash_file;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Uso: {} <arquivo> [hash]", args[0]);
        return;
    }
    let path = &args[1];
    let hash = hash_file(path).expect("Falha ao calcular o hash do arquivo");
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    println!("SHA-256: {}", hex);

    if args.len() == 3 {
        let ref_hash = args[2].to_lowercase();
        if ref_hash == hex {
            println!("Arquivo AUTÊNTICO: hash confere.");
        } else {
            println!("Arquivo ALTERADO: hash NÃO confere.");
        }
    }
}
