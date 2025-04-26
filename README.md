# 🔐 SSL Validator| Script de teste de certificados

<div align="center">
  <img src="https://sdmntprsouthcentralus.oaiusercontent.com/files/00000000-23a8-61f7-90d3-47b4474d8581/raw?se=2025-04-26T02%3A05%3A31Z&sp=r&sv=2024-08-04&sr=b&scid=2a6d421f-a373-5553-b3e9-3d665a5d9e0f&skoid=fa7966e7-f8ea-483c-919a-13acfd61d696&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2025-04-26T00%3A45%3A34Z&ske=2025-04-27T00%3A45%3A34Z&sks=b&skv=2024-08-04&sig=YPorJsTfM8uCPEmbU77wwwoZAVKgQdvajYcQ/HIeyBE%3D" width="40%" alt="SSL Validator Banner">
  
<div align="center">
  <a href="https://github.com/rafcsx/ssl-tester">
    <img src="https://img.shields.io/badge/Repositório-%23181717.svg?&style=for-the-badge&logo=github&logoColor=white"/>
  </a>
  <a href="https://pypi.org/project/ssl-tester-pro">
    <img src="https://img.shields.io/badge/PyPI-%233776AB.svg?&style=for-the-badge&logo=pypi&logoColor=white"/>
  </a>
</div>

## 🔍 Visão geral

**Ferramenta Python** para validação completa de certificados SSL/TLS com:

- Verificação de formato PEM/X.509
- Teste de conexão SSL real
- Análise de datas de validade
- Matching entre certificado e chave privada

```mermaid
graph LR
    A[Certificado] --> B[Validação]
    B --> C[Formato]
    B --> D[Datas]
    B --> E[Chave]
    C --> F[PEM válido]
    D --> G[Não expirado]
    E --> H[Correspondência]
```

## 🛠️ Tecnologias

<div align="center">
  <img src="https://skillicons.dev/icons?i=python,ssl,docker,bash,nginx,linux,vscode" alt="Tecnologias"/>
</div>

## 🎥 Demonstração/use

[![Assista a demonstração](https://img.youtube.com/vi/YT1utyOM4dM/0.jpg)](https://www.youtube.com/watch?v=YT1utyOM4dM)

## 📌 Exemplo de Saída

```
[✓] Certificado validado com sucesso!
- Válido de: Jan 1 2023 até Dec 31 2024
- Emissor: Let's Encrypt
- Protocolo: TLS 1.3
- Cipher Suite: TLS_AES_256_GCM_SHA384
```

## 🛡️ Funcionalidades principais

1. **Validação Completa de Certificados**
   - Verificação de formato PEM
   - Checagem de datas de validade
   - Análise de correspondência com chave privada

2. **Teste de Conexão SSL**
   - Servidor HTTPS local para testes
   - Análise de protocolos suportados
   - Verificação de cipher suites

3. **Interface Amigável**
   - Efeitos visuais interativos
   - Relatórios detalhados
   - Logs completos

<div align="center">
  <img src="https://komarev.com/ghpvc/?username=rafcsx&label=Acessos&style=flat-square&color=blue"/>
</div>
