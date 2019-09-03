#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib
import socket

def extEuclideanAlg(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, gcd = extEuclideanAlg(b, a % b)
        return y, x - y * (a // b), gcd

def modInvEuclid(a, m):
    x, y, gcd = extEuclideanAlg(a, m)
    if gcd == 1:
        return x % m
    else:
        return None

def convert_to_utf(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def h(g):
    passphrase = b'eitn41 <3'
    g = convert_to_utf(g)
    # print(g+passphrase)
    return hashlib.sha1(g + passphrase).hexdigest()

def run_ha4b2():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.connect(("eitn41.eit.lth.se", 1337))

    # the p shall be the one given in the manual
    p_input = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF'
    p = int(p_input, 16)
    g = 2
    g1 = 2

    ##########################
    #### D-H Key Exchange ####
    ##########################

    g_x1 = soc.recv(4096).decode('utf8').strip()
    g_x1 = int(g_x1, 16)%p

    x2 = 4324
    g_x2 = pow(g, x2, p)
    #y = x2
    # print (y)

    g_x2_str = format(g_x2, 'x')
    soc.send(g_x2_str.encode('utf8'))
    print('\ng_x2 is correct?', soc.recv(4096).decode('utf8').strip())

    ########
    # Social Millionaire problem #
    ####

    g1_a2 = soc.recv(4096).decode('utf8').strip()
    b2 = 50
    g1_b2 = pow(g1, b2, p)
    g1_b2_str = format(g1_b2, 'x')
    soc.send(g1_b2_str.encode('utf8'))
    print ('g1_b2 is correct?', soc.recv(4096).decode('utf8').strip())

    g1_a3 = soc.recv(4096).decode('utf8').strip()
    b3 = 60
    g1_b3 = pow(g1, b3, p)
    g1_b3_str = format(g1_b3, 'x')
    soc.send(g1_b3_str.encode('utf8'))
    print('g1_b3 is correct?', soc.recv(4096).decode('utf8').strip())

    g3 = pow(int(g1_a3, 16), b3, p)
    Pa = soc.recv(4096).decode('utf8').strip()
    b = 70
    Pb = pow(g3, b, p)
    Pb_str = format(Pb, 'x')
    soc.send(Pb_str.encode('utf8'))
    print('Pb is correct?', soc.recv(4096).decode('utf8').strip())

    g_xy = pow(g_x1, x2, p)
    y = int(h(g_xy), 16)
    g2 = pow(int(g1_a2, 16), b2, p)
    Qa = soc.recv(4096).decode('utf8').strip()
    g1_b = pow(g1, b, p)
    g2_y = pow(g2, y, p)
    Qb = (g1_b*g2_y)%p
    Qb_str = format(Qb, 'x')
    soc.send(Qb_str.encode('utf8'))
    print('Qb is correct?', soc.recv(4096).decode('utf8').strip())

    QaQbinv_a3 = soc.recv(4096).decode('utf8').strip()
    Qbinv = modInvEuclid(Qb, p)
    QaQbinv_b3 = pow( int(Qa, 16)*Qbinv, b3, p)
    QaQbinv_b3_str = format(QaQbinv_b3, 'x')
    soc.send(QaQbinv_b3_str.encode('utf8'))
    print('QaQbinv_b3 is correct?', soc.recv(4096).decode('utf8').strip())

    print('All good in Auth?', soc.recv(4096).decode('utf8').strip())

    # print ("test", soc.recv(4096).decode('utf8').strip())
    #msg = 'b7856e181fac9483d87066d2bc38a8c673ab1e8a'
    msg = 'f6cf0a76b63bbba613a217b6d2f40c795756c4d8'
    msg_int = int(msg, 16)
    msg_e = msg_int ^ g_xy
    msg_str = format(msg_e, 'x')
    soc.send(msg_str.encode('utf8'))
    print('Msg answer:', soc.recv(4096).decode('utf8').strip())

    soc.close()

run_ha4b2()
