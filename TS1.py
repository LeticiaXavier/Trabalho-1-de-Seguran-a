# Implementação do S-DES (Simplified DES)
# Letícia Xavier - 190142685

# Função de permutação 
def permutar(bits, tabela):
    return ''.join(bits[i - 1] for i in tabela)

# Permutação P10 e P8 para gerar subchaves a partir da chave inicial
def gerar_chaves(chave):
    # Permutação P10
    p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    chave_p10 = permutar(chave, p10)

    # Dividindo em duas partes para realizar o shift circular
    esquerda, direita = chave_p10[:5], chave_p10[5:]
    
    # Shift 1 à esquerda em cada metade
    esquerda1 = esquerda[1:] + esquerda[0]
    direita1 = direita[1:] + direita[0]

    # Permutação P8 para subchave 1
    p8 = [6, 3, 7, 4, 8, 5, 10, 9]
    k1 = permutar(esquerda1 + direita1, p8)

    # Shift adicional (2 posições) para gerar a segunda subchave
    esquerda2 = esquerda1[2:] + esquerda1[:2]
    direita2 = direita1[2:] + direita1[:2]
    k2 = permutar(esquerda2 + direita2, p8)

    return k1, k2

# Função XOR simples entre dois bits binários
def xor(bits1, bits2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))

# Função Fk (parte central do S-DES)
def fk(bits, chave):
    # Expansão/permutação E/P
    ep = [4, 1, 2, 3, 2, 3, 4, 1]
    s0 = [[1, 0, 3, 2],
          [3, 2, 1, 0],
          [0, 2, 1, 3],
          [3, 1, 3, 2]]
    s1 = [[0, 1, 2, 3],
          [2, 0, 1, 3],
          [3, 0, 1, 0],
          [2, 1, 0, 3]]
    p4 = [2, 4, 3, 1]

    esquerda, direita = bits[:4], bits[4:]
    direita_exp = permutar(direita, ep)
    xorado = xor(direita_exp, chave)

    # Processando S-Boxes
    esquerda_sbox = xorado[:4]
    direita_sbox = xorado[4:]

    linha_s0 = int(esquerda_sbox[0] + esquerda_sbox[3], 2)
    coluna_s0 = int(esquerda_sbox[1] + esquerda_sbox[2], 2)
    s0_valor = format(s0[linha_s0][coluna_s0], '02b')

    linha_s1 = int(direita_sbox[0] + direita_sbox[3], 2)
    coluna_s1 = int(direita_sbox[1] + direita_sbox[2], 2)
    s1_valor = format(s1[linha_s1][coluna_s1], '02b')

    sbox_result = s0_valor + s1_valor
    p4_result = permutar(sbox_result, p4)

    return xor(esquerda, p4_result) + direita

# Função principal de cifra S-DES
def sdes_cifrar(bits, chave):
    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    ip_inv = [4, 1, 3, 5, 7, 2, 8, 6]

    k1, k2 = gerar_chaves(chave)
    bits = permutar(bits, ip)
    bits = fk(bits, k1)
    bits = bits[4:] + bits[:4]  # Swap
    bits = fk(bits, k2)
    return permutar(bits, ip_inv)

# Mesmo processo de cifra, mas subchaves invertidas
def sdes_decifrar(bits, chave):
    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    ip_inv = [4, 1, 3, 5, 7, 2, 8, 6]

    k1, k2 = gerar_chaves(chave)
    bits = permutar(bits, ip)
    bits = fk(bits, k2)
    bits = bits[4:] + bits[:4]  # Swap
    bits = fk(bits, k1)
    return permutar(bits, ip_inv)

# ECB (Electronic Code Book) - cada bloco é cifrado isoladamente
def modo_ecb(texto, chave, cifrar=True):
    resultado = []
    for i in range(0, len(texto), 8):
        bloco = texto[i:i+8]
        if cifrar:
            resultado.append(sdes_cifrar(bloco, chave))
        else:
            resultado.append(sdes_decifrar(bloco, chave))
    return resultado

# CBC (Cipher Block Chaining) - cada bloco depende do anterior (com XOR)
def modo_cbc(texto, chave, iv, cifrar=True):
    resultado = []
    anterior = iv
    for i in range(0, len(texto), 8):
        bloco = texto[i:i+8]
        if cifrar:
            entrada = xor(bloco, anterior)
            cifrado = sdes_cifrar(entrada, chave)
            resultado.append(cifrado)
            anterior = cifrado
        else:
            decifrado = sdes_decifrar(bloco, chave)
            original = xor(decifrado, anterior)
            resultado.append(original)
            anterior = bloco
    return resultado

# Teste simples com 4 blocos de 8 bits
texto_original = "11010111011011001011101011110000"
chave = "1010000010"
iv = "11110000"

# Parte I - Teste básico S-DES com um único bloco
bloco_teste = texto_original[:8]
cifrado = sdes_cifrar(bloco_teste, chave)
decifrado = sdes_decifrar(cifrado, chave)

print("Parte I - S-DES Básico:")
print("Texto Cifrado:  ", cifrado)
print("Texto Decifrado:", decifrado)

# Parte II - ECB
print("\nParte II - ECB e CBC:\n")
print("Modo ECB:")
cifrados_ecb = modo_ecb(texto_original, chave, cifrar=True)
for i, c in enumerate(cifrados_ecb):
    print(f"Bloco {i+1} Cifrado:  {c}")
decifrados_ecb = modo_ecb(''.join(cifrados_ecb), chave, cifrar=False)
for i, d in enumerate(decifrados_ecb):
    print(f"Bloco {i+1} Decifrado: {d}")

# Parte III - CBC
print("\nModo CBC:")
cifrados_cbc = modo_cbc(texto_original, chave, iv, cifrar=True)
for i, c in enumerate(cifrados_cbc):
    print(f"Bloco {i+1} Cifrado:  {c}")
decifrados_cbc = modo_cbc(''.join(cifrados_cbc), chave, iv, cifrar=False)
for i, d in enumerate(decifrados_cbc):
    print(f"Bloco {i+1} Decifrado: {d}")
