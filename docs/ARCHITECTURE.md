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

### 2.7. Controle de Fluxo SENDME (`circuit.go`, `stream.go`)
- **Janela de Circuito:** Inicializada em 1000 células (`CircWindowInit`). A cada célula `RELAY_DATA` recebida, a janela decrementa. Ao atingir o limiar de 900 (`CircWindowThreshold`), o cliente envia uma célula `RELAY_SENDME` (streamID 0) para o endpoint do circuito e repõe 100 células na janela.
- **Janela de Stream:** Inicializada em 500 células (`StreamWindowInit`). A cada célula `RELAY_DATA` recebida no stream, a janela decrementa. Ao atingir 450, o cliente emite `RELAY_SENDME` (com o streamID específico) e repõe 50 células.
- **Pacotes de Envio (Packaging Window):** O cliente bloqueia ou aguarda confirmações `RELAY_SENDME` se a janela de envio atingir zero, respeitando estritamente `tor-spec.txt §7.3`.

### 2.8. Guards Persistentes em Disco (`guards.go`)
- O Torogo persiste nós Guard primários no arquivo `~/.torogo/guards.json` (ou caminho definido via `WithGuardFile`).
- Mitiga ataques de correlação estatística através do reuso contínuo do mesmo nó Guard por até 60 dias.
- Realiza rotação inteligente caso o nó fique offline (`fail_count >= 3`) ou deixe de ter a flag `Guard` no consenso.

### 2.9. Onion Services v3 (.onion) (`onion.go`)
- Suporte a endereços `.onion` v3 de 56 caracteres Base32 conforme `rend-spec-v3.txt`.
- Validação estrita do checksum SHA3-256 e versão (`0x03`).
- Cálculo do time-period de consenso (`86400s` com offset de `12h`) e estruturas para handshake de Rendezvous (`RELAY_ESTABLISH_RENDEZVOUS`, `RELAY_RENDEZVOUS_ESTABLISHED`, `RELAY_INTRODUCE1`).

### 2.10. Pluggable Transports e Pontes SOCKS5 (`pt.go`)
- **Discador SOCKS5 RFC 1928 Puro:** Permite tunelar o handshake de enlace TLS com o nó Guard/Bridge através de proxies locais.
- **Parser de Linhas Bridge:** Decodifica linhas oficiais do Tor Project (`Bridge obfs4 IP:Port Fingerprint cert=... iat-mode=...`).
- **Compatibilidade Tor PT v2.1:** Gerenciamento de subprocessos de transporte ofuscado (`TOR_PT_MANAGED_TRANSPORT_VER=1`) com leitura de anúncios `CMETHOD socks5`.

### 2.11. Resolução Remota de DNS e Prevenção de DNS Leak (`circuit.go`, `client.go`)
- **Zero DNS Leak:** Em conexões `DialContext`, o nome de domínio nunca é resolvido pela máquina local ou ISP. A string de domínio é enviada diretamente dentro da célula cifrada `RELAY_BEGIN` para o Exit Node remoto, que efetua a consulta.
- **`Resolve` Remoto (`RELAY_RESOLVE` / `RELAY_RESOLVED`):** Permite resolver nomes de host remotamente através do circuito de 3 saltos sem abrir uma conexão TCP, de forma idêntica ao utilitário `tor-resolve` do cliente oficial C.

### 2.12. Servidor SOCKS5 Local Drop-in (`socks_server.go`)
- Implementa um servidor SOCKS5 RFC 1928 completo via `client.ListenSOCKS5(addr)`.
- Permite que qualquer aplicativo do sistema operacional (cURL, Firefox, navegadores, Telegram, bots) aponte para `127.0.0.1:9050` e utilize o Torogo como substituto drop-in para o binário do Tor em C.

### 2.13. Seleção de Caminho Ponderada e Exclusão de Famílias (`path-spec.txt`)
- Extrai `bandwidth-weights` e larguras de banda individuais do consenso para realizar seleção balanceada ponderada por capacidade real de rede (`Wgg`, `Wgd`, `Wmg`, `Wmm`, `Wee`, `Wed`).
- Validação estrita de famílias de nós (`sameFamily`), garantindo que nós pertencentes à mesma família declarada ou mesma sub-rede `/16` nunca compartilhem o mesmo circuito.

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
