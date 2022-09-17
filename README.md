# SC-Criptografia_RSA-Python
## Gerador/Verificador de Assinaturas RSA em Arquivos.

* Parte I: Geração de chaves
	- 1. Geração de chaves (p e q primos com no mínimo de 1024 bits).

* Parte II: Cifra simétrica
	- 1. Geração de chaves simétrica.
	- 2. Cifração simétrica de mensagem (AES modo CTR).

* Parte III: Geração da assinatura
	- 1. Cálculo de hashes da mensagem em claro (função de hash SHA-3).
	- 2. Assinatura da mensagem (cifração do hash da mensagem usando OAEP).
	- 3. Formatação do resultado (caracteres especiais e informações para verificação em BASE64).

* Parte IV: Verificação:
	- 1. Parsing do documento assinado e decifração da mensagem (de acordo com a formatação usada, no caso BASE64).
	- 2. Decifração da assinatura (decifração do hash).
	- 3. Verificação (cálculo e comparação do hash do arquivo).
