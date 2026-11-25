# Torogo: Pure Go Tor Client & Library

Cliente e biblioteca Tor minimalista implementado **100% em Go puro**, utilizando exclusivamente a biblioteca padrão (`crypto/*`, `net/*`, `encoding/*`, `compress/zlib`). Não possui dependências de terceiros no `go.mod`, não utiliza CGO e não depende do binário do sistema `tor`.

O `torogo` pode ser utilizado como uma **biblioteca em outros projetos Go** (oferecendo abstrações padrão como `net.Dialer` e `*http.Client`) ou executado diretamente como **aplicação/CLI**.

---

## Características

- **100% Go Standard Library**: Zero dependências externas no `go.mod` / `go.sum`, compila com `CGO_ENABLED=0`.
- **API Idiomática para Bibliotecas**:
  - `torogo.NewClient(ctx, opts...)` para inicialização com bootstrap e cache de consenso.
  - `client.DialContext(ctx, "tcp", "host:port")` implementando `net.Dialer` e retornando `net.Conn`.
  - `client.HTTPClient()` retornando um `*http.Client` pronto para uso com tráfego 100% roteado via Tor.
  - `client.Transport()` expondo o `*http.Transport` subjacente para customizações.
- **Suporte a Onion Services (.onion v3)**:
  - Validação estrita de endereços `.onion` v3 (56 caracteres em Base32, checksum SHA3-256 e versão 0x03).
  - Primitivas para handshake de Rendezvous e Link Specifiers conforme `rend-spec-v3.txt`.
- **Controle de Fluxo SENDME**:
  - Implementação completa das janelas de fluxo a nível de circuito (1000 células) e de stream (500 células) per `tor-spec.txt §7.3`.
  - Emissão automática de `RELAY_SENDME` ao decrementar 100 células no circuito e 50 células no stream, permitindo transferências contínuas de grandes volumes de dados sem engasgos ou pausas pelos relays.
- **Guards Persistentes em Disco**:
  - Persistência automática do nó Guard primário em disco (`~/.torogo/guards.json`), mitigando ataques de correlação estatística e rastreamento a longo prazo.
  - Reutilização inteligente com fallback e opções de customização (`WithGuardFile`, `WithDisableGuards`).
- **Pluggable Transports & SOCKS5 Bridges**:
  - Discador SOCKS5 RFC 1928 integrado em Go puro para rotear enlaces através de pontes de ofuscação (obfs4, Snowflake, meek).
  - Parser de linhas `Bridge` padrão do Tor (`Bridge obfs4 IP:Port Fingerprint cert=... iat-mode=...`).
  - Gerenciador de subprocessos compatível com a especificação Tor PT v2.1 IPC (`TOR_PT_MANAGED_TRANSPORT_VER=1`).
- **Compatível com Distroless**: Pronto para ser empacotado em imagens mínimas e estáticas (`gcr.io/distroless/static-debian12`).
- **Bootstrap de Diretório**:
  - Download do consenso de microdescritores das Directory Authorities oficiais.
  - Validação criptográfica das assinaturas de consenso (RSA-SHA256 PKCS#1 v1.5).
  - Download e verificação de integridade SHA-256 dos microdescritores dos relays.
- **Seleção de Caminho**:
  - Seleção balanceada de nós Guard, Middle e Exit com suporte a qualquer porta de destino.
  - Isolamento de sub-redes (`/16`) para evitar relays correlacionados no mesmo circuito.
- **Link Handshake (v4/v5)**:
  - Troca de células `VERSIONS`, `CERTS`, `AUTH_CHALLENGE` e `NETINFO`.
  - Validação de certificados de relay Ed25519 (tipos 4 e 5) contra as chaves de identidade.
- **Criação de Circuitos de 3 Saltos**:
  - `CREATE2` para o nó de guarda e `EXTEND2` sucessivos para o nó intermediário e de saída.
  - Handshake de chaves moderno **ntor** (Curve25519 / X25519, HKDF-SHA256, HMAC-SHA256).
- **Criptografia em Camadas (Onion Routing)**:
  - Criptografia simétrica AES-128-CTR e digest contínuo SHA-1 por salto (forward/backward).
- **Streams e Conexão TLS**:
  - Implementa a interface `net.Conn` sobre células `RELAY_BEGIN`, `RELAY_DATA`, `RELAY_CONNECTED` e `RELAY_END`.
  - Negociação TLS 1.2/1.3 sobre o stream para requisição HTTPS segura.

---

## Uso como Biblioteca (Go Library)

Para usar o `torogo` em outro projeto:

```bash
go get github.com/pedromol/torogo
```

### Exemplo 1: Requisições HTTP com `*http.Client`

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/pedromol/torogo"
)

func main() {
	ctx := context.Background()

	// Inicializa o cliente Tor (baixa e valida o consenso)
	client, err := torogo.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Obtém um *http.Client padrão do Go roteado via Tor
	httpClient := client.HTTPClient()

	resp, err := httpClient.Get("https://check.torproject.org/api/ip")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
```

### Exemplo 2: Conexão TCP genérica com `DialContext` (`net.Conn`)

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/pedromol/torogo"
)

func main() {
	ctx := context.Background()

	client, err := torogo.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Disca qualquer endereço TCP através de um circuito de 3 saltos
	conn, err := client.DialContext(ctx, "tcp", "check.torproject.org:443")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("Conectado com sucesso via Tor!", conn.RemoteAddr())
}
```

---

## Estrutura do Projeto

```
torogo/
├── client.go                 # API pública da biblioteca (Client, DialContext, HTTPClient)
├── client_test.go            # Testes da API pública
├── cmd/
│   └── torogo/
│       └── main.go           # CLI de exemplo utilizando a biblioteca torogo
├── internal/
│   └── tor/
│       ├── cell.go           # Estruturas e enquadramento de células Tor (fixas e variáveis)
│       ├── cell_test.go      # Testes de codificação de células
│       ├── certs.go          # Parsers de certificados de autoridade RSA e certificados Ed25519
│       ├── circuit.go        # Gerenciamento de circuitos, CREATE2/EXTEND2 e camadas onion
│       ├── consensus.go      # Autoridades de diretório, parser e validação de consenso
│       ├── crypto.go         # ntor handshake (X25519/HKDF), RSA raw e criptografia auxiliar
│       ├── directory.go      # Cliente HTTP de diretório, fetch de microdescritores e seleção de caminho
│       ├── directory_test.go # Testes de autoridades e utilitários de diretório
│       ├── embedded_certs.go # Suporte a certificados de autoridade embutidos
│       ├── flow_control_test.go # Testes de janelas e fluxo SENDME
│       ├── guards.go         # Gerenciamento e persistência de Guards em disco
│       ├── guards_test.go    # Testes de persistência e seleção de Guards
│       ├── link.go           # Conexão de enlace TLS e handshake de link
│       ├── ntor_test.go      # Testes do handshake ntor
│       ├── onion.go          # Endereços Onion v3, checksum SHA3-256 e rendezvous
│       ├── onion_test.go     # Testes de validação de endereços .onion
│       ├── pt.go             # Pluggable Transports, discador SOCKS5 e bridges
│       ├── pt_test.go        # Testes de pontes e cliente SOCKS5
│       └── stream.go         # Abstração de stream multiplexada sobre o circuito (net.Conn)
├── docs/
│   ├── ARCHITECTURE.md       # Documentação detalhada da arquitetura e protocolo interno
│   └── plans/
│       └── pure-go-tor-plan.md # Especificação e plano de implementação original
├── Dockerfile                # Build multi-stage para container distroless estático
└── go.mod                    # Módulo Go puro (sem dependências)
```

---

## Pré-requisitos

- Go 1.24 ou superior (testado com Go 1.27).
- Acesso à internet para conexão com os relays e autoridades da rede Tor.

---

## Como Executar o Exemplo CLI

### 1. Executando localmente

```bash
go run ./cmd/torogo
```

Saída esperada:
```text
initializing torogo client...
making HTTP request over Tor...
circuit established
IsTor=true IP=192.42.116.68
```

### 2. Rodando os testes unitários

```bash
go test -v ./...
```

### 3. Compilando binário estático

```bash
CGO_ENABLED=0 go build -ldflags "-s -w" -o torclient ./cmd/torogo
./torclient
```

### 4. Executando via Docker (Distroless)

```bash
docker build -t torogo .
docker run --rm torogo
```

---

## Referências da Especificação Tor

- [tor-spec.txt](https://spec.torproject.org/tor-spec): Formato de células, handshakes de link, ntor e crypto de relay.
- [dir-spec.txt](https://spec.torproject.org/dir-spec): Protocolo de diretórios, consensos de microdescritores e assinaturas.
- [cert-spec.txt](https://spec.torproject.org/cert-spec): Formato e extensões de certificados Ed25519.
