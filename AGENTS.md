# AGENTS.md — Torogo Project Guidelines for AI Agents

Este documento contém contexto técnico, restrições e diretrizes essenciais para agentes de IA que realizam manutenção ou evolução deste repositório.

---

## 1. Visão Geral e Princípios Fundamentais

O **Torogo** é um cliente da rede Tor implementado do zero em **Go puro**.
Os seguintes princípios **nunca** devem ser violados:

1. **Zero Dependências Externas (R1 & R2)**:
   - O projeto deve usar **exclusivamente** pacotes da biblioteca padrão do Go (`crypto/*`, `net/*`, `encoding/*`, `compress/zlib`, `io`, `time`, etc.).
   - Não adicione bibliotecas externas ao `go.mod` (`go get` não deve ser usado para bibliotecas terceiras).
   - Não utilize CGO (`CGO_ENABLED=0`).
   - Não dependa de binários externos do sistema operacional (como o binário `tor`).
2. **Binário Estático & Distroless (R3)**:
   - O binário deve compilar estaticamente e rodar em containers minimalistas como `gcr.io/distroless/static-debian12`.
3. **Fidelidade à Especificação Tor**:
   - Todo comportamento na wire-spec deve respeitar estritamente as especificações oficiais: `tor-spec.txt`, `dir-spec.txt` e `cert-spec.txt`.

---

## 2. Mapa da Arquitetura

- `client.go` (raiz, `package torogo`):
  - API pública principal da biblioteca.
  - Implementa `NewClient`, `DialContext`, `Dial`, `Transport` e `HTTPClient`.
  - Cache de consenso em memória (`getConsensus`) com validação temporal thread-safe (`sync.RWMutex`).
  - Encapsula streams e circuitos em `torConn` para fechamento automático de circuitos e enlaces TLS ao fechar a conexão `net.Conn`.

- `cmd/torogo/main.go`:
  - Aplicação CLI e teste de integração executável.
  - Utiliza diretamente a biblioteca `torogo.NewClient(ctx)` e `client.HTTPClient()`.

- `internal/tor/`:
  - `cell.go`: Células fixas (509 bytes) e variáveis. Comandos `VERSIONS`, `CERTS`, `NETINFO`, `CREATE2`, `CREATED2`, `RELAY`, `RELAY_EARLY`.
  - `link.go`: Enlace TLS sobre a porta ORPort. Link handshake v4/v5 (`VERSIONS` → `CERTS` → `AUTH_CHALLENGE` → `NETINFO`).
  - `circuit.go`: Criação de circuitos (`NewCircuit`, `Extend`) e gerenciamento de camadas de criptografia (onion wrapping).
  - `crypto.go`: Implementação do handshake **ntor** (Curve25519/X25519, HKDF-SHA256, HMAC-SHA256) e verificação RSA PKCS#1 v1.5 raw.
  - `consensus.go`: Estrutura de dados de consenso, lista de Directory Authorities, parser de consenso de microdescritores e verificação de assinaturas das autoridades.
  - `directory.go`: Download HTTP de documentos de consenso e microdescritores (`/tor/micro/d/...`), seleção aleatória ponderada de nós para o circuito (`SelectPathForPort`).
  - `certs.go`: Parser de certificados de chave de autoridade RSA (`dir-key-certificate-version 3`) e certificados Ed25519 (tipos 4 e 5).
  - `stream.go`: Implementa `net.Conn` para multiplexar streams TCP sobre células de relay (`RELAY_BEGIN`, `RELAY_DATA`, `RELAY_CONNECTED`, `RELAY_END`).

---

## 3. Peculiaridades Críticas do Protocolo (Armadilhas Comuns)

Ao alterar ou estender o código, atente-se para os seguintes detalhes da especificação:

### Consenso e Assinaturas (`dir-spec.txt`)
- **Signed Range:** O texto assinado pelas autoridades de diretório começa no início de `network-status-version` e termina exatamente no espaço logo após a primeira ocorrência de `directory-signature ` (inclusive).
- **Linha `directory-signature`:** O formato é `directory-signature [algorithm] <identity-digest> <signing-key-digest>`. A assinatura criptográfica **não** está nesta linha; ela vem encapsulada no bloco PEM subsequente (`-----BEGIN SIGNATURE-----`).
- **Microdescritores:** As URLs de download `/tor/micro/d/<digest>` usam Base64 **sem padding** (`base64.RawStdEncoding`). Usar padding `=` causará erro HTTP 404 nos servidores de diretório.

### Célula NETINFO (`tor-spec.txt §4.5`)
- O payload de `NETINFO` contém:
  - `Timestamp` [4 bytes]
  - `OTHERADDR`: `ATYPE` [1 byte: 0x04 para IPv4], `ALEN` [1 byte: 4], `AVAL` [4 bytes]
  - `NMYADDR` [1 byte: 0x00 se não divulgado]
- Não envie `ATYPE = 0`, pois relays encerram a conexão imediatamente.

### Célula CREATED2 (`tor-spec.txt §5.1`)
- Diferente de `CREATE2` (que inclui `HTYPE` de 2 bytes), a célula de resposta `CREATED2` **não** possui o campo `HTYPE`.
- O payload inicia diretamente com `HLEN` (2 bytes, big-endian) seguido por `HDATA` (`HLEN` bytes).

### Certificados Ed25519 (`cert-spec.txt §2`)
- Na seção de extensões dos certificados Ed25519, cada extensão possui:
  - `ExtLen` [2 bytes big-endian]
  - `ExtType` [1 byte]
  - `ExtFlags` [1 byte]
  - `ExtData` [`ExtLen` bytes]

---

## 4. Diretrizes de Desenvolvimento e Testes

- **Testes Unitários**: Sempre execute `go test -v ./...` antes de concluir qualquer alteração.
- **Teste de Integração Real**: Para verificar a saúde contra a rede Tor viva, execute:
  ```bash
  go run ./cmd/torogo
  ```
  O comando deve imprimir `circuit established` e `IsTor=true` com o IP de saída.
- **Formatação e Lint**: Siga o padrão idiomático Go (`gofmt` / `go vet`).
