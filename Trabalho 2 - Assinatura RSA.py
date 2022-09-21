# Alunos:
    # Paulo Victor França de Souza - 20/0042548;
    # Thais Fernanda de Castro Garcia - 20/0043722.

# Disciplina:
    # Dep. Ciência da Computação - Universidade de Brasília (UnB),
    # CIC0201 - Segurança Computacional (2022.1).
    # Prof. João José Costa Gondim - Turma 1.

# Implementação:
    # Gerador e verificador de assinaturas RSA em arquivos.

# -------------------------------------------------------------------------------------------------------------------------------------------- #

import random
import math
import base64
import os
import sys
import hashlib
from pathlib import Path
from math import ceil

# -------------------------------------------------------------------------------------------------------------------------------------------- #

# Parte I: Geração de chaves
    # 1. Geração de chaves (p e q primos com no mínimo de 1024 bits).

def miller_rabin(n,k): # Teste de primalidade Miller-Rabin.
    if n == 2 or n == 3:
        return True

    if n%2 == 0:
        return False

    r,s = 0, n-1
    while s%2 == 0:
        r+=1
        s//=2
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a,s,n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = pow(x,2,n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gera_primos(): # Geração de chaves primas com no mínimo 1024 bits com teste de primalidade (Miller-Rabin).
    n = random.getrandbits(1024)
    if miller_rabin(n,40) == True:
        return n
    return gera_primos()

sys.setrecursionlimit(1500)

while True:
    try:
        p = gera_primos() # Geração do número p primo.  
        #q=46640454671839385106850250675383258434676003351166912666160526956520491901114665456214661841736790161068130887295026690797559491065360814698474839924841760550398249505553794577075432906321867094966744571489612148950919744767430312552583360861853826802525351976284092025209493800853573153099456456279851870211
        q = gera_primos() # Geração do número q primo.
        #p=128034973046262643891053453305460574682893773852533297518701052948562111102766522321365821084617013220456274709012571417347906657782127561710429770765540512858002907040240236283924778994667266814293418268591854261439959832812154332344575306836679437998536528501144037288706437327144037679655182263728270998413
        break
    except: # RecursionError
        None

def encontra_inverso_mod(a, m): # Encontra o inverso modular de a % m, que é o número x tal que a * x % m = 1.
    if math.gcd(a, m) != 1: # Nenhum inverso modular caso a e m não sejam primos relativos.
        return None

    u1, u2, u3 = 1, 0, a # Calcula usando o algoritmo de Euclides estendido.
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

n = p*q # Cálculo de n = p.q

fn = (p-1)*(q-1) # Cálculo de f(n) = (p - 1).(q - 1).

e=0
while (math.gcd(fn, e) != 1): # Encontrar um e, tal que o MDC (máximo divisor comum) de f(n) & e = 1, onde 1 < e < f(n).
    e = random.randrange(2, fn)

d = encontra_inverso_mod(e, fn) # Encontrar um d tal que ed mod mod f(n) = 1

chave_privada = (d, n) # Chave privada RSA.
chave_publica = (e, n) # Chave pública RSA.

print("\n# -------------------- Parte I: Geração de chaves -------------------- #\n")
print("* 1. Geração de chaves (p e q primos com no mínimo de 1024 bits):")
print("  - p com teste de primalidade (Miller-Rabin) =", p)
print("  - q  com teste de primalidade (Miller-Rabin) =", q)
#print("  - n =", n)
#print("  - f(n) =", fn)
#print("  - e =", e)
#print("  - d =", d)
#print("  - Chave privada:", chave_privada)
#print("  - Chave pública:", chave_publica)

# -------------------------------------------------------------------------------------------------------------------------------------------- #

# Parte II: Cifra simétrica
	# 1. Geração de chaves simétrica.
	# 2. Cifração simétrica de mensagem (AES modo CTR).

chave_aes_ctr = bytes([random.getrandbits(8) for i in range(16)]) # Chave AES modo CTR.

def extrair_chave_para_arredondar(chave_expandida, round):
  return [fileira[round*4: round*4 + 4] for fileira in chave_expandida]

def quebrar_em_grades_de_16(s):
    all = []

    for i in range(len(s)//16):
        b = s[i*16: i*16 + 16]
        grade = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                grade[i].append(b[i + j*4])
        all.append(grade)

    return all

aes_sbox = [
    [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16), int(
        '30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
    [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16), int(
        'ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
    [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16), int(
        '34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
    [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16), int(
        '07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
    [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16), int(
        '52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
    [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16), int(
        '6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
    [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16), int(
        '45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
    [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16), int(
        'bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
    [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16), int(
        'c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
    [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16), int(
        '46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
    [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16), int(
        'c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
    [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16), int(
        '6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
    [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16), int(
        'e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
    [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16), int(
        '61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
    [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16), int(
        '9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
    [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16), int(
        '41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
]

aes_sbox_reversa = [
    [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16), int(
        'bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
    [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16), int(
        '34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
    [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16), int(
        'ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
    [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16), int(
        '76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
    [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16), int(
        'd4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
    [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16), int(
        '5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
    [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16), int(
        'f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
    [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16), int(
        'c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
    [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16), int(
        '97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
    [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16), int(
        'e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
    [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16), int(
        '6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
    [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16), int(
        '9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
    [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16), int(
        'b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
    [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16), int(
        '2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
    [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16), int(
        'c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
    [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16), int(
        'e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]
]

def lookup(byte):
    x = byte >> 4
    y = byte & 15
    return aes_sbox[x][y]

def lookup_reverso(byte):
    x = byte >> 4
    y = byte & 15
    return aes_sbox_reversa[x][y]

def expande_chave(chave, rounds):
    rcon = [[1, 0, 0, 0]]

    for _ in range(1, rounds):
        rcon.append([rcon[-1][0]*2, 0, 0, 0])
        if rcon[-1][0] > 0x80:
            rcon[-1][0] ^= 0x11b

    chave_grade = quebrar_em_grades_de_16(chave)[0]

    for round in range(rounds):
        ultima_coluna = [fileira[-1] for fileira in chave_grade]
        ultima_coluna_rodada_passo = rodada_fileira_esquerda(ultima_coluna)
        ultima_coluna_sbox_passo = [lookup(b) for b in ultima_coluna_rodada_passo]
        ultima_coluna_rcon_passo = [ultima_coluna_sbox_passo[i]
                                 ^ rcon[round][i] for i in range(len(ultima_coluna_rodada_passo))]

        for r in range(4):
            chave_grade[r] += bytes([ultima_coluna_rcon_passo[r]
                                  ^ chave_grade[r][round*4]])

        for i in range(len(chave_grade)): # Mais três colunas para ir
            for j in range(1, 4):
                chave_grade[i] += bytes([chave_grade[i][round*4+j]
                                      ^ chave_grade[i][round*4+j+3]])

    return chave_grade

def rodada_fileira_esquerda(fileira, n=1):
    return fileira[n:] + fileira[:n]

def multiplica_por_2(v):
    s = v << 1
    s &= 0xff
    if (v & 128) != 0:
        s = s ^ 0x1b
    return s

def multiplica_por_3(v):
    return multiplica_por_2(v) ^ v


def mescla_colunas(grade):
    nova_grade = [[], [], [], []]
    for i in range(4):
        col = [grade[j][i] for j in range(4)]
        col = mescla_coluna(col)
        for i in range(4):
            nova_grade[i].append(col[i])
    return nova_grade


def mescla_coluna(coluna):
    r = [
        multiplica_por_2(coluna[0]) ^ multiplica_por_3(
            coluna[1]) ^ coluna[2] ^ coluna[3],
        multiplica_por_2(coluna[1]) ^ multiplica_por_3(
            coluna[2]) ^ coluna[3] ^ coluna[0],
        multiplica_por_2(coluna[2]) ^ multiplica_por_3(
            coluna[3]) ^ coluna[0] ^ coluna[1],
        multiplica_por_2(coluna[3]) ^ multiplica_por_3(
            coluna[0]) ^ coluna[1] ^ coluna[2],
    ]
    return r


def add_sub_chave(bloco_grade, chave_grade):
    r = []

    for i in range(4): # 4 fileiras na grade.
        r.append([])
        
        for j in range(4): # 4 valores em cada fileira.
            r[-1].append(bloco_grade[i][j] ^ chave_grade[i][j])
    return r

def aes(chave, data):
    pad = bytes(16 - len(data) % 16) # Primeiro precisa preencher os dados com \x00 e dividi-los em blocos de 16.
    
    if len(pad) != 16:
        data += pad

    grades = quebrar_em_grades_de_16(data)
    
    chave_expandida = expande_chave(chave, 11) # Agora precisa expandir a chave para as várias rodadas e aplicar a chave original nos blocos antes de começar as rodadas.

    temp_grades = []

    arredonda_chave = extrair_chave_para_arredondar(chave_expandida, 0)

    for grade in grades:
        temp_grades.append(add_sub_chave(grade, arredonda_chave))

    grades = temp_grades

    for round in range(1, 10):
        temp_grades = []
        
        for grade in grades:
            sub_bytes_passo = [[lookup(val) for val in fileira] for fileira in grade]
            shift_fileiras_passo = [rodada_fileira_esquerda(
                sub_bytes_passo[i], i) for i in range(4)]
            mescla_coluna_passo = mescla_colunas(shift_fileiras_passo)
            arredonda_chave = extrair_chave_para_arredondar(chave_expandida, round)
            add_sub_chave_passo = add_sub_chave(mescla_coluna_passo, arredonda_chave)
            temp_grades.append(add_sub_chave_passo)

        grades = temp_grades

    temp_grades = []

    arredonda_chave = extrair_chave_para_arredondar(chave_expandida, 10) # Uma rodada final sem as colunas mescladas.

    for grade in grades:
        sub_bytes_passo = [[lookup(val) for val in fileira] for fileira in grade]
        shift_fileiras_passo = [rodada_fileira_esquerda(
            sub_bytes_passo[i], i) for i in range(4)]
        add_sub_chave_passo = add_sub_chave(shift_fileiras_passo, arredonda_chave)
        temp_grades.append(add_sub_chave_passo)

    grades = temp_grades

    int_fluxo = []
    
    for grade in grades:
        for coluna in range(4):
            for fileira in range(4):
                int_fluxo.append(grade[fileira][coluna])

    return bytes(int_fluxo)


def inc_bytes(a): # Gera um novo array de bytes com o valor incrementado em 1.
    lista_bytes = list(a)
    for i in reversed(range(len(lista_bytes))):
        if lista_bytes[i] == 0xFF:
            lista_bytes[i] = 0
        else:
            lista_bytes[i] += 1
            break
    return bytes(lista_bytes)

def gera_chave_aes_ctr(chave_aes_ctr): # Gerador de chaves AES modo CTR.
    chave_aes_ctr_ = chave_aes_ctr
    while True:
        chave_aes_ctr_ = inc_bytes(chave_aes_ctr_)
        yield chave_aes_ctr_

def divide_mensagem(conteudo_mensagem, tamanho=16): # Divide conteúdo da mensagem em blocos.
    return [conteudo_mensagem[i:i+16] for i in range(0, len(conteudo_mensagem), tamanho)]

with open(Path(__file__).absolute().parent / "mensagem.txt", "rb") as file: # Leitura do arquivo "mensagem.txt"
    conteudo = file.read()

tamanho_bloco = 16 - (len(conteudo) % 16) # Conteúdo do bloco.
bloco = bytes([tamanho_bloco] * tamanho_bloco)
conteudo += bloco
conteudo = base64.encodebytes(conteudo)


def xor_bloco(mensagem, chave_aes_ctr):
    result = []
    for a,b in zip(mensagem, chave_aes_ctr):
        result.append(a^b)

    resultado_lista_bytes = bytearray(result)
    
    return resultado_lista_bytes

resultado_blocos = []
#chave = int.from_bytes(input('Digite a chave para encriptacao: ').encode(), byteorder='big').to_bytes(16, byteorder='big')
chave = bytes([random.getrandbits(8) for i in range(16)])
for mensagem_bloco, chave_aes_ctr_bloco in zip(divide_mensagem(conteudo), gera_chave_aes_ctr(chave_aes_ctr)): # Criptografia AES modo CTR.
    resultado_blocos.append(xor_bloco(
        aes(chave, chave_aes_ctr_bloco),
        mensagem_bloco
    ))

cifracao_aes_resultado = base64.encodebytes(b''.join(resultado_blocos)) # Resultado do AES modo CTR.

decifracao_blocos = []
for mensagem_bloco, chave_aes_ctr_bloco in zip(divide_mensagem(base64.decodebytes(cifracao_aes_resultado)), gera_chave_aes_ctr(chave_aes_ctr)): # Descriptografia do AES modo CTR.
    decifracao_blocos.append(xor_bloco(
        aes(chave, chave_aes_ctr_bloco),
        mensagem_bloco
    ))

decifracao_aes_resultado = base64.decodebytes(b''.join(decifracao_blocos)) # Resultado da descriptografia do AES modo CTR.

print("\n# -------------------- Parte II: Cifra simétrica -------------------- #\n")
print("* 1. Geração de chaves simétrica:")
print("  - Chave AES modo CTR =", base64.encodebytes(chave_aes_ctr))
print("* 2. Cifração simétrica de mensagem (AES modo CTR):")
print("  - Cifração AES modo CTR =", base64.encodebytes(cifracao_aes_resultado))

# -------------------------------------------------------------------------------------------------------------------------------------------- #

# Parte III: Geração da assinatura
	# 1. Cálculo de hashes da mensagem em claro (função de hash SHA-3).
	# 2. Assinatura da mensagem (cifração do hash da mensagem usando OAEP).
	# 3. Formatação do resultado (caracteres especiais e informações para verificação em BASE64).

def sha3_224(m):
    sha3 = hashlib.sha3_224()
    sha3.update(m)
    return sha3.digest()

resultado_sha = sha3_224(conteudo)

mensagem = base64.encodebytes(resultado_sha)

def mgf1(seed, mlen):
    t = b''
    hlen = 28

    for c in range(0, ceil(mlen / hlen)):
        c_ = c.to_bytes(4, byteorder='big')
        t += sha3_224(seed + c_)

    return t[:mlen]

def codifica_oaep(m, k, label = b'', mgf1 = mgf1) -> bytes:
    mlen = len(m)
    lhash = sha3_224(label)
    hlen = len(lhash)
    ps = b'\x00' * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b'\x01' + m
    seed = os.urandom(hlen)
    db_mask = mgf1(seed, k - hlen - 1)
    masked_db = xor_bloco(db, db_mask)
    seed_mask = mgf1(masked_db, hlen)
    masked_seed = xor_bloco(seed, seed_mask)
    return b'\x00' + masked_seed + masked_db

def cifra(mensagem, chave_publica):
    e, n = chave_publica
    return pow(mensagem, e, n)

def cifra_raw(mensagem, chave_publica):
    k = chave_publica[1].bit_length() // 8
    c = cifra(
        int.from_bytes(mensagem, byteorder='big'),
        chave_publica
    )
    return c.to_bytes(length=k+1, byteorder='big')

hash_length = 28 

k = chave_publica[1].bit_length() // 8 # Calcula o número de octetos na chave.

cifrado_oaep = codifica_oaep(mensagem, k) # Cifração OAEP.
c = cifra_raw(cifrado_oaep, chave_publica)

def oaep_decifra(c: bytes, k: int, label: bytes = b'', sha3_224 = sha3_224) -> bytes:
    clen = len(c)
    lhash = sha3_224(label)
    hlen = len(lhash)
    _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
    seed_mask = mgf1(masked_db, hlen)
    seed = xor_bloco(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - hlen - 1)
    db = xor_bloco(masked_db, db_mask)
    _lhash = db[:hlen]
    assert lhash == _lhash
    i = hlen
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
        else:
            raise Exception()
    m = db[i:]
    return m

def decifra(c: int, chave_privada):
    d, n = chave_privada
    return pow(c, d, n)

def decifra_raw(mensagem, chave_privada):
    k = chave_privada[1].bit_length() // 8
    m = decifra(int.from_bytes(mensagem, byteorder='big'), chave_privada)
    return m.to_bytes(k, byteorder='big')

print("\n# -------------------- Parte III: Geração da assinatura -------------------- #\n")
print("* 1. Cálculo de hashes da mensagem em claro (função de hash SHA-3):")
print('  - SHA3_224 =', base64.encodebytes(resultado_sha))
print("* 2. Assinatura da mensagem (cifração do hash da mensagem usando OAEP):")
print("  - Hash da mensagem cifrada =", cifrado_oaep)
print("* 3. Formatação do resultado (caracteres especiais e informações para verificação em BASE64):")
print("  - Hash da mensagem cifrada formatada =", base64.encodebytes(cifrado_oaep))

# -------------------------------------------------------------------------------------------------------------------------------------------- #

# Parte IV: Verificação:
	# 1. Parsing do documento assinado e decifração da mensagem (de acordo com a formatação usada, no caso BASE64).
	# 2. Decifração da assinatura (decifração do hash).
	# 3. Verificação (cálculo e comparação do hash do arquivo).

k = chave_privada[1].bit_length() // 8
hlen = 28
#print(len(c), k)
oaep_decifrado = oaep_decifra(decifra_raw(c, chave_privada), k)

print("\n# -------------------- Parte IV: Verificação -------------------- #\n")
print("* 1. Parsing do documento assinado e decifração da mensagem (de acordo com a formatação usada, no caso BASE64):")
print("  - Mensagem decifrada =", decifracao_aes_resultado)
print("* 2. Decifração da assinatura (decifração do hash):")
print("  - Assinatura decifrada =", oaep_decifrado)
print("* 3. Verificação (cálculo e comparação do hash do arquivo):")
print("  - Verificação =")
print("   ", base64.encodebytes(resultado_sha),"= ",oaep_decifrado,"?")
if base64.encodebytes(resultado_sha) == oaep_decifrado:
    print("    >> Os dois são iguais!")
else:
    print("    >> Os dois não são iguais!")


