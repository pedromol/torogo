# Arquitetura do Torogo

Este documento descreve detalhadamente o funcionamento interno do **Torogo**, uma implementação completa e independente do protocolo Tor escrita em **Go puro**, sem qualquer dependência externa ou CGO.

---

## 1. Visão Geral em Camadas

```
+-------------------------------------------------------------------+
|                           Aplicação                               |
|          (cmd/torogo ou projeto externo usando a lib)            |
+---------------------------------+---------------------------------+
|          *http.Client           |        client.DialContext       |
|    (http.Transport com Tor)     |         (net.Conn / TCP)        |
+---------------------------------+---------------------------------+
|                       torogo.Client (client.go)                   |
|     (Cache de Consenso, Pooling de Conexões, Lifecycle Seguro)    |
+-------------------------------------------------------------------+
|                     Camada de Stream (stream.go)                  |
|     (Multiplexação TCP, RELAY_BEGIN / RELAY_DATA / RELAY_END)     |
+-------------------------------------------------------------------+
|                    Camada de Circuito (circuit.go)                |
|      (Onion Wrapping AES-128-CTR, SHA-1 Digest, CREATE2/EXTEND2)  |
+-------------------------------------------------------------------+
|                     Handshake ntor (crypto.go)                    |
|       (Curve25519 / X25519, HKDF-SHA256, HMAC-SHA256 Auth)        |
+-------------------------------------------------------------------+
|                     Enlace TLS & Células (link.go, cell.go)       |
|        (Link Protocol 4/5, VERSIONS, CERTS, NETINFO, Células 509B)|
+-------------------------------------------------------------------+
|                     Diretório & Consenso (directory.go)           |
|        (Bootstrap de Consenso Microdesc, Assinaturas RSA-SHA256)  |
+-------------------------------------------------------------------+
```

---

## 2. Componentes e Ciclo de Vida

### 2.1. Bootstrap de Diretório e Consenso (`consensus.go`, `directory.go`)
1. **Download do Consenso:** O cliente consulta uma das 10 Directory Authorities conhecidas via requisição HTTP (`/tor/status-vote/current/consensus-microdesc`).
2. **Validação de Assinaturas:**
   - O documento assinado cobre o intervalo entre o início de `network-status-version` até o espaço após a primeira linha `directory-signature ` (inclusive).
   - O hash SHA-256 desse intervalo é verificado contra a assinatura RSA PKCS#1 v1.5 contida no bloco PEM de cada autoridade.
   - O consenso é aceito somente se possuir quórum de assinaturas válidas (`N/2 + 1`).
3. **Download de Microdescritores:**
   - Para cada nó candidato, o hash SHA-256 do microdescritor é requisitado via `/tor/micro/d/<hash>` sem padding base64.
   - O microdescritor fornece a chave estática do nó (`ntor-onion-key`), a chave de identidade Ed25519 (`id ed25519`) e a política de saída (`p accept/reject`).

### 2.2. Seleção de Caminho (`SelectPathForPort`)
- O circuito é formado por 3 nós distintos:
  - **Guard:** Deve ter as flags `Guard`, `Running`, `Valid`.
  - **Middle:** Deve ter as flags `Fast`, `Running`, `Valid`.
  - **Exit:** Deve ter a flag `Exit` (sem `BadExit`) e sua política de saída deve aceitar a porta solicitada (ex: 443 ou 80).
- **Isolamento `/16`:** Nenhum dos três nós pode pertencer à mesma sub-rede `/16` (ou IPv6 equivalente), evitando correlação de tráfego.

### 2.3. Enlace TLS e Link Handshake (`link.go`, `cell.go`)
1. Abre conexão TLS com a porta `ORPort` do nó Guard com `InsecureSkipVerify: true` (pois relays usam certificados autoassinados).
2. **Troca de Células de Link:**
   - Envia `VERSIONS` com suporte aos protocolos 4 e 5.
   - Lê `VERSIONS` do relay e valida se o protocolo 4 é suportado.
   - Lê células `CERTS`, extraindo os certificados Ed25519 tipos 4 (Signing Key) e 5 (TLS Link Key).
   - Valida criptograficamente os certificados Ed25519 contra a chave master (`edID`) obtida no microdescritor.
   - Ignora `AUTH_CHALLENGE` e células de padding.
   - Envia célula `NETINFO` preenchida com timestamp atual e endereço do relay em formato TLV (`0x04` IPv4, length 4).

### 2.4. Construção do Circuito e Handshake ntor (`circuit.go`, `crypto.go`)
1. **CREATE2 (Guard):**
   - Gera par de chaves efêmero X25519 no cliente (`x`, `X`).
   - Monta payload `CREATE2`: Handshake Type `0x0002` (ntor) + 20 bytes NodeID + 32 bytes Onion Key (`B`) + 32 bytes Public Key (`X`).
   - O Guard responde com `CREATED2`: 2 bytes `HLEN` (64) + 32 bytes Public Key do Guard (`Y`) + 32 bytes Server Auth (`AUTH`).
   - O cliente executa o algoritmo **ntor**: deriva `xy = x*Y` e `xb = x*B`, valida o HMAC de autenticação do servidor e extrai via HKDF as chaves do salto (`Df`, `Db`, `Kf`, `Kb`).
2. **EXTEND2 (Middle e Exit):**
   - Envia célula `RELAY_EARLY` com comando `RelayExtend2` contendo link specifiers do próximo nó e o handshake ntor correspondente.
   - O nó anterior estende a conexão e responde com `RelayExtended2`.
   - O cliente processa o payload e adiciona o novo `Hop` ao circuito.

### 2.5. Criptografia em Camadas (Onion Routing)
- Cada célula de relay enviada é criptografada progressivamente com AES-128-CTR do último salto até o primeiro (`Exit → Middle → Guard`).
- Cada nó intermediário remove sua camada de cifragem antes de repassar a célula ao nó seguinte.
- Células recebidas pelo cliente são decifradas progressivamente (`Guard → Middle → Exit`) até que o campo `recognized == 0` e o digest SHA-1 bata com o esperado para aquele salto.

### 2.6. Multiplexação de Streams (`stream.go`)
- Implementa `net.Conn` padrão do Go.
- Envia célula `RELAY_BEGIN` com o host e porta de destino (ex: `check.torproject.org:443\x00`).
- Ao receber `RELAY_CONNECTED`, o stream está estabelecido.
- Dados são trocados via células `RELAY_DATA` (máximo 498 bytes por célula).
- Encerramento via `RELAY_END`.

---

## 3. A Estrutura Pública `torogo.Client`

O pacote raiz `torogo` encapsula toda a complexidade acima:

```go
type Client struct {
    mu        sync.RWMutex
    consensus *tor.Consensus
    opts      clientOptions
    closed    bool
}
```

- **Cache de Consenso Thread-Safe:** Evita downloads repetidos do consenso de ~2MB enquanto ele estiver dentro da janela de validade (`ValidAt(now)`).
- **`DialContext`:** Compatível com a assinatura padrão de dialers do ecossistema Go.
- **`HTTPClient` e `Transport`:** Permite que qualquer biblioteca cliente HTTP (ou o próprio `http.DefaultClient`) navegue de forma transparente através da rede Tor.
