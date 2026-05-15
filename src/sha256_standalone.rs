use std::convert::TryInto;

/// O estado inicial para o SHA-256, derivado das partes fracionárias das raízes quadradas
/// dos primeiros 8 números primos (2..19).
const H256_256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// As constantes de rodada para o SHA-256. Elas representam os primeiros 32 bits das partes
/// fracionárias das raízes cúbicas dos primeiros 64 números primos (2..311).
const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Função auxiliar para converter um bloco de 64 bytes (512 bits) em um array de 16 palavras de 32 bits.
/// O SHA-256 opera em palavras de 32 bits, portanto o fluxo de bytes é lido no formato Big Endian.
/// Pega um bloco de 64 bytes e junta grupos de 4 bytes para formar um 'u32'.
pub(crate) fn to_u32s(block: &[u8; 64]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for i in 0..16 {
        out[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    out
}

/// Função central de compressão
/// Ela recebe o estado atual de 256 bits (8 palavras) e um bloco de mensagem de 512 bits (64 bytes).
/// Ela processa o bloco de mensagem para misturá-lo com o estado usando operações lógicas.
/// Consiste em: expandir os 16 blocos originais para 64 palavras, rodar o loop principal de compressão
/// de 64 rodadas aplicando operações como Choose (ch) e Majority (maj), e por fim, adicionar o resultado
/// compactado de volta ao estado atual.
pub(crate) fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    // Prepara a expansão da mensagem (message schedule) `w`.
    // Expandimos as 16 palavras de 32 bits em 64 palavras usando deslocamentos lógicos e operações XOR.
    let mut w = [0u32; 64];
    let initial_words = to_u32s(block);
    
    for i in 0..16 {
        w[i] = initial_words[i];
    }
    
    for i in 16..64 {
        // s0 é uma combinação de rotações para a direita e um deslocamento para a direita de w[i-15]
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        // s1 é uma combinação de rotações para a direita e um deslocamento para a direita de w[i-2]
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    // Inicializa as variáveis de trabalho com o estado atual.
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // loop principal de compressão. Executa 64 vezes.
    for i in 0..64 {
        // s1: Soma 1 da variável E (maiúsculo)
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        // ch: Choose (Escolha: se e for 1, escolhe bit de f, senão escolhe bit de g)
        let ch = (e & f) ^ ((!e) & g);
        
        // t1 é o valor temporário calculado usando as variáveis de trabalho, a constante da rodada e a palavra expandida.
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K32[i]).wrapping_add(w[i]);
        
        // s0: Soma 0 da variável A (maiúsculo)
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        // maj: Majority (Maioria: verdadeiro se pelo menos dois dentre a, b ou c forem verdadeiros)
        let maj = (a & b) ^ (a & c) ^ (b & c);
        
        // t2 é o valor temporário usado para atualizar 'a'
        let t2 = s0.wrapping_add(maj);

        // Atualiza as variáveis de trabalho
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    // Adiciona o pedaço comprimido ao estado atual.
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Ponto de entrada principal para calcular o hash SHA-256 de uma fatia (slice) de bytes.
/// Ele lida com o preenchimento (padding) da mensagem e sua divisão em blocos de 64 bytes para a função de compressão.
/// Ele processa blocos completos, em seguida, adiciona o bit '1' (byte 0x80) e zeros de padding.
/// Se não houver espaço suficiente no último bloco para o tamanho da mensagem, um bloco extra é criado.
/// Por fim, adiciona o tamanho original e retorna o hash de 32 bytes finalizado.

#[cfg(test)]
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut state = H256_256;
    let length_in_bits = (data.len() as u64).wrapping_mul(8);

    // Processa todos os blocos completos de 64 bytes diretamente
    let mut chunk_start = 0;
    while chunk_start + 64 <= data.len() {
        let chunk = &data[chunk_start..chunk_start + 64];
        compress_block(&mut state, chunk.try_into().unwrap());
        chunk_start += 64;
    }

    // Lida com os bytes restantes, o bit `1`, os zeros de preenchimento e o comprimento da mensagem
    let mut final_block = [0u8; 64];
    let remaining_bytes = data.len() - chunk_start;
    
    // Copia os bytes restantes para o bloco final
    final_block[..remaining_bytes].copy_from_slice(&data[chunk_start..]);
    
    // Anexa o bit '1' (byte 0x80) logo após os dados da mensagem
    final_block[remaining_bytes] = 0x80;

    // Se não houver espaço suficiente para o comprimento de 8 bytes no final deste bloco
    // (ou seja, remaining_bytes >= 56), precisaremos de um bloco extra.
    if remaining_bytes >= 56 {
        // Comprime este bloco
        compress_block(&mut state, &final_block);
        
        // Prepara um bloco vazio para o comprimento
        final_block = [0u8; 64];
    }

    // Anexa o comprimento original da mensagem em bits como um inteiro big-endian de 64 bits bem no final
    final_block[56..64].copy_from_slice(&length_in_bits.to_be_bytes());
    
    // Comprime o último bloco
    compress_block(&mut state, &final_block);

    // Combina o estado final em um array de 32 bytes (big-endian)
    let mut result = [0u8; 32];
    for (i, &word) in state.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }

    result
}

pub struct Sha256 {
    state: [u32; 8],    // Os 8 registradores H0..H7
    buffer: [u8; 64],   // Bytes parciais do bloco atual
    buf_len: usize,     // Quantos bytes válidos há no buffer
    total_len: u64,     // Total de bytes absorvidos (para o padding final)
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: H256_256,
            buffer: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Absorve qualquer quantidade de bytes. Pode ser chamado quantas vezes quiser.
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;

        // Se já há bytes no buffer, tenta completar um bloco
        if self.buf_len > 0 {
            let space = 64 - self.buf_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            self.total_len += to_copy as u64;
            pos += to_copy;

            if self.buf_len == 64 {
                compress_block(&mut self.state, &self.buffer);
                self.buf_len = 0;
            }
        }

        // Processa blocos completos direto do slice de entrada (zero-copy)
        while pos + 64 <= data.len() {
            let block: &[u8; 64] = data[pos..pos + 64].try_into().unwrap();
            compress_block(&mut self.state, block);
            self.total_len += 64;
            pos += 64;
        }

        // Guarda os bytes restantes no buffer para a próxima chamada
        let remaining = data.len() - pos;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[pos..]);
            self.buf_len = remaining;
            self.total_len += remaining as u64;
        }
    }

    /// Aplica o padding e retorna o hash final. Consome a struct.
    pub fn finalize(mut self) -> [u8; 32] {
        let length_in_bits = self.total_len.wrapping_mul(8);

        // Padding: bit '1' logo após os dados
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        // Zera o resto do buffer
        for byte in &mut self.buffer[self.buf_len..] {
            *byte = 0;
        }

        // Se não couber o tamanho (8 bytes) neste bloco, comprime e abre um novo
        if self.buf_len > 56 {
            compress_block(&mut self.state, &self.buffer);
            self.buffer = [0u8; 64];
        }

        // Escreve o tamanho original em bits no final do último bloco (big-endian)
        self.buffer[56..64].copy_from_slice(&length_in_bits.to_be_bytes());
        compress_block(&mut self.state, &self.buffer);

        // Serializa o estado final
        let mut result = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Testes contra os vetores de teste padrão do NIST para o SHA-256.
    #[test]
    fn test_nist_vectors() {
        // Converte string de hexa em array de bytes
        let decode_hex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };

        // String vazia
        let result = compute_sha256(b"");
        assert_eq!(
            result.as_slice(),
            decode_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").as_slice()
        );

        // "abc"
        let result = compute_sha256(b"abc");
        assert_eq!(
            result.as_slice(),
            decode_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").as_slice()
        );

        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let result = compute_sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            result.as_slice(),
            decode_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").as_slice()
        );
        
        // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        let result = compute_sha256(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(
            result.as_slice(),
            decode_hex("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1").as_slice()
        );
    }

    #[test]
    fn test_struct_equals_function() {
        let data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

        // Resultado da função original
        let expected = compute_sha256(data);

        // Resultado da nova struct (alimentando em pedaços)
        let mut hasher = Sha256::new();
        for chunk in data.chunks(7) { // os chunks aq sao irregulares de propósito
            hasher.update(chunk);
        }
        let result = hasher.finalize();

        assert_eq!(result, expected);
    }
}
