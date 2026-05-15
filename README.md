# SHA-256 e Autenticador
Projeto da aula de Criptografia ministrada pelo Prof. Escobar

Gera hashes SHA-256 de arquivos e verifica sua autenticidade comparando com uma hash fornecida.

## Compilar
```bash
cargo build --release
```
## Usar
Navegue até a pasta do binário:
```bash
cd target/release
```
**Gerar hash de um arquivo:**
```bash
./sha256 <arquivo>
```
**Verificar se uma hash pertence a um arquivo:**
```bash
./sha256 <arquivo> <hash>
```
## Testes NIST
```bash
cargo test
```
