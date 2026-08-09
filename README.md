# Phishing Email Analyzer

Ferramenta de linha de comando para apoiar a triagem de e-mails suspeitos.
Recebe um arquivo `.eml`, extrai tudo que importa (headers, corpo, URLs,
anexos), aplica heurísticas conhecidas de detecção de phishing e,
opcionalmente, cruza domínios/URLs/IPs com o VirusTotal e faz WHOIS para
checar a idade do domínio. No final, entrega um **score de 0 a 100** e um
veredito, com a lista de indicadores que pesaram na decisão — para você
revisar, não para substituir seu julgamento.

## Por que assim (e não uma "IA que decide se é phishing")

Um analista de SOC não confia em uma caixa preta que devolve "phishing:
sim/não". Confia em evidência: qual mecanismo de autenticação falhou, qual
domínio não bate, qual anexo é perigoso. Por isso a ferramenta é uma
**regras + score explicável**: cada indicador some ou não para o score, e
o relatório mostra exatamente por quê. Isso também facilita anexar a
evidência em um ticket/caso de escalonamento.

## O que ela verifica

| Categoria | O que é checado |
|---|---|
| **Autenticação** | Resultado de SPF/DKIM/DMARC (via `Authentication-Results`, o mesmo dado que soluções como Cisco CES/Proofpoint calculam); registro SPF/DMARC publicado no DNS do domínio remetente |
| **Identidade do remetente** | Divergência From vs. Reply-To vs. Return-Path; nome de exibição imitando marca conhecida (`"Itaú" <suporte@dominio-aleatorio.com>`) |
| **URLs** | Typosquatting (erro de digitação ou marca embutida como isca), texto do link ≠ destino real do `href`, encurtadores, domínios com punycode (homograph), IP literal no lugar de domínio, TLDs associados a abuso |
| **Anexos** | Extensões perigosas (`.exe`, `.js`, `.hta`, macro do Office...), extensão dupla (`fatura.pdf.exe`), hash SHA-256 de cada anexo |
| **Corpo do e-mail** | Linguagem de urgência/pressão ("sua conta será bloqueada", "clique aqui agora"...) |
| **Reputação externa** *(opcional)* | VirusTotal (domínios, URLs, IPs da cadeia `Received`), idade de registro via WHOIS |

A lista de marcas conhecidas (para spoofing de nome/typosquatting) já vem
com bancos e serviços comuns no cenário brasileiro (Itaú, Bradesco,
Santander, Caixa, BB, Nubank, Inter, Mercado Livre, Correios, Receita
Federal, Serasa, Claro, Embratel) + big techs (Microsoft, Google, Apple,
PayPal). Edite `analyzer/header_analysis.py` → `KNOWN_BRANDS` para
adicionar as marcas que fizerem sentido no seu contexto.

## Instalação

```bash
pip install -r requirements.txt
```

(`beautifulsoup4`, `python-whois` e `rich` são usados para, respectivamente,
achar links dentro de HTML, checar idade de domínio e formatar o output no
console — a ferramenta funciona sem eles, só com saída mais simples/menos
recursos.)

## Uso

Análise só com heurísticas locais (sem nenhuma chamada de rede):
```bash
python main.py --file suspeito.eml --offline
```

Análise completa, com DNS (SPF/DMARC reais) mas sem VirusTotal:
```bash
python main.py --file suspeito.eml
```

Com VirusTotal + WHOIS (recomendado para casos que já passaram na triagem
inicial e você quer confirmar):
```bash
export VT_API_KEY="sua_chave_gratuita_aqui"   # https://www.virustotal.com/gui/my-apikey
python main.py --file suspeito.eml --check-reputation
```

Salvando relatório para anexar num ticket:
```bash
python main.py --file suspeito.eml --check-reputation \
    --json output/caso123.json --html output/caso123.html
```

Lendo de outro lugar que não um arquivo (ex.: e-mail colado via stdin):
```bash
cat suspeito.txt | python main.py
```

### Testando com as amostras incluídas

```bash
python main.py --file samples/phishing_sample.eml --offline   # deve dar ALTO RISCO
python main.py --file samples/legit_sample.eml --offline      # deve dar SEM INDICADORES
```

## Sobre o VirusTotal

- Conta gratuita = 4 requisições/minuto e ~500/dia. A ferramenta já respeita
  esse limite automaticamente (pausa entre chamadas), então uma análise
  com muitas URLs pode levar alguns minutos — é esperado, não travou.
- Se a URL nunca foi vista pelo VirusTotal antes, a consulta pode retornar
  "não encontrada" em vez de um veredito. A v3 pública de leitura não
  submete a URL automaticamente para análise (isso exigiria um endpoint de
  escrita separado, fora do escopo deste script de triagem passiva).
- O código do VirusTotal fica isolado em `analyzer/reputation.py` — trocar
  por outra fonte (urlscan.io, AlienVault OTX, etc.) é só adicionar outro
  client na mesma dataclass `VTVerdict`/padrão.

## Sobre o WHOIS

Em redes corporativas é comum a porta TCP/43 (protocolo WHOIS) estar
bloqueada por firewall. A ferramenta já lida com isso: se a consulta não
responder em alguns segundos, ela desiste daquele indicador específico e
segue a análise normalmente (o resto do relatório não é afetado).

## Interpretando o score

| Score | Veredito |
|---|---|
| 0 | Sem indicadores |
| 1–24 | Baixo risco — poucos sinais, vale uma checagem rápida |
| 25–54 | Suspeito — merece análise manual antes de descartar |
| 55+ | Alto risco — phishing provável |

Os pesos de cada regra estão no topo de `analyzer/scoring.py` e podem (e
devem) ser calibrados com base no que você for vendo no dia a dia — se um
indicador estiver gerando muito falso positivo no seu ambiente, é só
reduzir o peso dele ali.

## Limitações conhecidas (leia antes de confiar cegamente)

- **Não verifica assinatura DKIM criptograficamente** — usa o resultado já
  calculado pelo servidor de e-mail receptor (`Authentication-Results`),
  que é o que a maioria das soluções de e-mail security corporativas
  também expõe. Se você precisar re-verificar a assinatura do zero, dá
  para integrar a lib `dkimpy` em `header_analysis.py`.
- **Detecção de typosquatting é por distância de edição + lista fixa de
  marcas** — não substitui um feed de threat intel dedicado a domínios
  lookalike.
- **`extract_domain`/`_registrable_part` não usa a Public Suffix List
  completa** — para a maioria dos casos (`.com`, `.com.br`, `.net`...)
  funciona bem, mas pode errar em TLDs com sufixos incomuns de 3+ níveis.
- Isto é uma ferramenta de **apoio à triagem**, não um veredito automático.
  Score alto = investigar com prioridade; score baixo = provavelmente
  limpo, mas não é uma garantia absoluta.

## Estrutura do projeto

```
phishing_analyzer/
├── main.py                    # CLI
├── analyzer/
│   ├── parser.py               # leitura do .eml -> headers/corpo/URLs/anexos
│   ├── header_analysis.py      # SPF/DKIM/DMARC, spoofing de nome, mismatches
│   ├── url_analysis.py         # typosquatting, encurtadores, punycode, TLDs
│   ├── reputation.py           # VirusTotal, WHOIS, AbuseIPDB
│   ├── scoring.py              # motor de regras -> score + veredito
│   └── report.py               # saída console / JSON / HTML
├── samples/                    # e-mails de exemplo (1 phishing, 1 legítimo)
├── requirements.txt
└── .env.example
```

## Próximos passos sugeridos

- Integrar como Lambda/Cloud Function acionada por um encaminhamento de
  e-mail suspeito para uma caixa dedicada (ex.: `phishing@empresa.com`).
- Adicionar `urlscan.io` como segunda fonte de reputação de URL.
- Persistir os relatórios JSON em um índice (ex.: OpenSearch) para
  cruzar campanhas recorrentes (mesmo domínio/IP reaparecendo).
