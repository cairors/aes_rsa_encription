from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from hashlib import sha256, md5
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto import Random
from os import urandom
import Crypto.Util.number
import hmac
import re
import os

def geraChaveMac(arquivo):
        with open(arquivo, 'r') as myfile:
                mensagem = myfile.read()
        myfile.close()
        hash_msg = sha256(str.encode(mensagem))
        chave = hash_msg.hexdigest()
        return chave

def geraMac(arquivo):
        chave = geraChaveMac(arquivo)
        with open(arquivo, 'r') as myfile:
                mensagem = myfile.read()
        myfile.close()
        novo_mac = hmac.new(bytes(chave, 'utf-8'), bytes(mensagem, 'utf-8'), sha256).hexdigest()
        return novo_mac

def arqMac(arquivo):
        novo_mac = geraMac(arquivo)
        saida_mac = arquivo[:-4] + "_mac.txt"
        arq_mac = open(saida_mac, 'w')
        arq_mac.write(novo_mac)
        arq_mac.close()
        print("MAC salva no arquivo '%s'" % (saida_mac))

def arqChaveMac(arquivo):
        chave = geraChaveMac(arquivo)
        saida_chave = arquivo[:-4] + "_kmac.txt"
        chave_mac = open(saida_chave, 'w')
        chave_mac.write(chave)
        chave_mac.close()
        print("Chave MAC salva no arquivo '%s'" % (saida_chave))

def testaMac(in_file):
        arquivo = str(in_file)
        arquivo = arquivo[25:-29]
        hash_mac = str(in_file.read())
        hash_mac = str(hash_mac[-64:])
        with open(arquivo, 'r') as myfile:
                conteudo = myfile.read()
        conteudo = re.sub(hash_mac, '', str(conteudo))
        with open(arquivo, 'w') as myfile:
                myfile.seek(0)
                myfile.write(conteudo)
                myfile.truncate()
                myfile.close()
        o_mac = geraMac(arquivo)
        if hash_mac == o_mac:
                print("O MAC do arquivo é válido!")
        else:
                print("O MAC do arquivo é inválido!")

def geraSimK(arquivo, tamanho):
        chaveMac = arquivo[:-4] + "_kmac.txt"
        if tamanho == 16:
                with open(chaveMac, 'r') as myfile:
                        key_Mac = myfile.read()
                myfile.close()
                chaveHash = md5(str.encode(key_Mac))
                chaveSimetrica = chaveHash.hexdigest()
        elif tamanho == 32:
                with open(chaveMac, 'r') as myfile:
                        key_Mac = myfile.read()
                myfile.close()
                chaveHash = sha256(str.encode(key_Mac))
                chaveSimetrica = chaveHash.hexdigest()
        print("Chave simétrica gerada!")
        saida_simK = arquivo[:-4] + "_simk.txt"
        arq_simK = open(saida_simK, 'w')
        arq_simK.write(chaveSimetrica)
        arq_simK.close()
        print("Chave simétrica salva no arquivo '%s'" % (saida_simK))

def derive_key_and_iv(password, salt, key_length, iv_length):
        d = d_i = b''
        while len(d) < key_length + iv_length:
                d_i = md5(d_i + str.encode(password) + salt).digest()
                d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

def rsaKeyGen(senha):
        private = RSA.generate(2048)
        enc_key = private.exportKey(passphrase = senha, pkcs=8, protection="scryptAndAES128-CBC")
        arq_pr = senha + ".pr"
        pr_key = open(arq_pr, 'wb')
        pr_key.write(private.exportKey())
        arq_pu = senha + ".pu"
        pub_key = open(arq_pu, 'wb')
        pub_key.write(private.publickey().exportKey())
        print("Chaves RSA criadas!")

def encRSA(arquivo, senha):
        rsaKeyGen(senha)
        arq_pu = senha + ".pu"
        with open(arq_pu, 'rb') as myfile:
                pub_key = RSA.importKey(myfile.read())
        arq_macK = arquivo[:-4] + "_kmac.txt"
        with open(arq_macK, 'r') as myfile:
                chave_mac = myfile.read()
        arq_simK = arquivo[:-4] + "_simk.txt"
        with open(arq_simK, 'r') as myfile:
                chave_sim = myfile.read()
        chaves = chave_mac + chave_sim
        cripto_chaves = arquivo[:-4] + "_ecrk.txt"
        cipher = PKCS1_v1_5.new(pub_key)
        chaves = chaves
        arq_chaves = open(cripto_chaves, 'wb')
        arq_chaves.write(cipher.encrypt(bytes(chaves, 'utf-8')))
        arq_chaves.close()
        print("Criptografia assimétrica realizada!")
        print("Chaves salvas no arquivo '%s'" % (cripto_chaves))

def decRSA(arquivo, senha):
        arq_enc = arquivo[:-8] + "_ecrk.txt"
        with open(arq_enc, 'rb') as myfile:
                cripto_chaves = myfile.read()
        arq_dec = arquivo[:-8] + "_dcrk.txt"
        arq_pr = senha + ".pr"
        with open(arq_pr, 'rb') as myfile:
                prv_key = RSA.importKey(myfile.read())
        cipher = PKCS1_v1_5.new(prv_key)
        dsize = SHA.digest_size
        sentinel = Random.new().read(15+dsize)
        with open(arq_dec, 'wb') as myfile:
                myfile.write(cipher.decrypt(cripto_chaves, sentinel))
        with open(arq_dec, 'r') as myfile:
                chaves = myfile.read()
        destino_macK = arquivo[:-8] + "_kmac.txt"
        destino_simK = arquivo[:-8] + "_simk.txt"
        chave_mac = chaves[:64]
        arq_macK = open(destino_macK, 'w')
        arq_macK.write(chave_mac)
        chave_sim = chaves[64:96]
        arq_simK = open(destino_simK, 'w')
        arq_simK.write(chave_sim)
        print("Chaves descriptografadas!")
        print("Chaves salvas nos arquivos '%s' e '%s'" % (destino_macK, destino_simK))

def encriptar(in_file, out_file, password, key_length, modo, hash_mac, salt_header=''):
        ins_mac = str(in_file)
        ins_mac = ins_mac[26:-6] + "1.txt"
        with open(ins_mac, 'wb') as myfile:
                myfile.write(in_file.read())
                myfile.write(bytes(hash_mac, 'utf-8'))
                myfile.close()
        bs = AES.block_size
        salt = urandom(bs - len(salt_header))
        key, iv = derive_key_and_iv(password, salt, key_length, bs)
        if modo == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
        elif modo == "CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write(str.encode(salt_header) + salt)
        finished = False
        while not finished:
                with open(ins_mac, 'rb') as myfile:
                        chunk = myfile.read(1024 * bs)
                        if len(chunk) == 0 or len(chunk) % bs != 0:
                                padding_length = (bs - len(chunk) % bs) or bs
                                chunk += str.encode(padding_length * chr(padding_length))
                                finished = True
                        out_file.write(cipher.encrypt(chunk))
                        myfile.close()
        os.remove(ins_mac)
        print("Criptografia realizada!")

def decriptar(in_file, out_file, password, key_length, modo, salt_header=''):
        bs = AES.block_size
        salt = in_file.read(bs)[len(salt_header):]
        key, iv = derive_key_and_iv(password, salt, key_length, bs)
        if modo == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
        elif modo == "CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
                chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
                if len(next_chunk) == 0:
                        padding_length = chunk[-1]
                        chunk = chunk[:-padding_length]
                        finished = True
                out_file.write(bytes(x for x in chunk))
        print("Descriptografia realizada!")

def main():
        op_sair = False
        while not op_sair:
                op_fin = False
                while not op_fin:
                        opcao = input("Informe a opção desejada (1-Criptografar / 2-Descriptografar / 3-Sair): ")
                        if opcao == "1":
                                op_fin = True
                        elif opcao == "2":
                                op_fin = True
                        elif opcao == "3":
                                op_fin = True
                                op_sair = True
                                exit()
                        else:
                                print("Opção inválida!")
                                print()
                                op_fin = False
                arq_fin = False
                while not arq_fin:
                        arquivo = input("Informe o arquivo: ")
                        arq_fin = os.path.isfile(arquivo)
                        if not arq_fin:
                                print("Arquivo não existe!")
                                print()
                op_met = False
                while not op_met:
                        metodo = input("Informe o modo desejado (ECB / CBC): ")
                        metodo = metodo.upper()
                        if metodo == "ECB":
                                op_met = True
                        elif metodo == "CBC":
                                op_met = True
                        else:
                                print("Método desconhecido!")
                                print()
                                op_met = False
                tam_fin = False
                while not tam_fin:
                        tamanho = input("Informe o tamanho desejado (128 / 256): ")
                        if tamanho == "128":
                                key_length = 16
                                tam_fin = True
                        elif tamanho == "256":
                                key_length = 32
                                tam_fin = True
                        else:
                                print("Tamanho não permitido!")
                                print()
                                tam_fin = False
                if opcao == "1":
                        nome = input("Informe seu nome: ")
                        nome = nome.lower()
                        chaveMac = geraChaveMac(arquivo)
                        print("Chave MAC gerada!")
                        hashMac = geraMac(arquivo)
                        print("MAC gerado!")
                        arqMac(arquivo)
                        arqChaveMac(arquivo)
                        geraSimK(arquivo, key_length)
                        arqSimK = arquivo[:-4] + "_simk.txt"
                        with open(arqSimK, 'r') as myfile:
                                senha = myfile.read()
                        if arquivo[(len(arquivo) - 4)::] == ".txt":
                                txt_fin = False
                                while not txt_fin:
                                        txt = input("Deseja codificar o arquivo ou somente o texto?(1-Arquivo/2-Texto) ")
                                        if txt == "1":
                                                saida = arquivo + ".enc"
                                                txt_fin = True
                                        elif txt == "2":
                                                saida = arquivo[:-4] + "_enc.txt"
                                                txt_fin = True
                                        else:
                                                print("Opção inválida!")
                                                print()
                                                txt_fin = False
                        else:
                                saida = arquivo + ".enc"
                        with open(arquivo, 'rb') as in_file, open(saida, 'wb') as out_file:
                                encriptar(in_file, out_file, senha, key_length, metodo, hashMac)
                        encRSA(arquivo, nome)
                        print()
                elif opcao == "2":
                        nome = input("Informe o nome para verificação das chaves: ")
                        decRSA(arquivo, nome)
                        arqSimK = arquivo[:-8] + "_simk.txt"
                        with open(arqSimK, 'r') as myfile:
                                senha = myfile.read()
                        if arquivo.endswith(".enc"):
                                saida = arquivo[:-4]
                        elif arquivo.endswith("_enc.txt"):
                                saida = arquivo[:-8] + ".txt"
                        else:
                                saida = arquivo[:-4] + "_dec" + arquivo[(len(arquivo) - 4)::]
                        with open(arquivo, 'rb') as in_file, open(saida, 'wb') as out_file:
                                decriptar(in_file, out_file, senha, key_length, metodo)
                        with open(saida, 'r') as in_file:
                                testaMac(in_file)
                        print()

if __name__ == "__main__":
        main() 
