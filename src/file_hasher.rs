use std::fs::File;
use std::io::{self, BufReader, Read};

use crate::sha256_standalone::Sha256;

// Essa função faz o hashing só que sem carregar todo o arquivo de uma vez na memoria se não pode explodir
pub fn hash_file(path: &str) -> io::Result<[u8; 32]> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut hasher = Sha256::new();
    let mut chunk = [0u8; 8192]; // 8KB por leitura

    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }

    Ok(hasher.finalize())
}
