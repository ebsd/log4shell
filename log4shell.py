# Description:
#     Utilise https://github.com/lunasec-io/lunasec/releases/tag/v1.1.2-log4shell
#     puis automatise le "scan" chaque machine.
#     En sortie (scan.txt), on obtient la liste des machines possédant une lib log4j et sa version.
#     Ce code ne respecte probablement pas le meilleures pratiques. Il a été écrit
#     dans l'urgence et par un non professionnel du dev. Il peut être nettement amélioré.
#
# Licence: WTFPL
# Date:    15.12.2021
# Author:  ebsd
# Update:  
#         15.12.2021 : Ne scanner que le /local et /opt pour cette itération
#         16.12.2021 : ajout d'un test lsof de la lib pour connaitre l'état lib utilisée / non utilisée (dès 10h45)
#         17.12.2021 : ajout de fonctions pour tester la présence du contournement Dlog4j2.formatMsgNoLookups=true (qui ne semble pas suffisant)
#
# Prérequis:
#      - paramiko
#
# Erreurs / exceptions non gérées:
#      - Timeout waiting scp response
#      - paramiko.ssh_exception.SSHException: Unable to connect to vmlp-01026: [Errno 24] Too many open files
#      - KeyError: 'Id' : impossible de se connecter à SG ? Retenter. Sinon peut être pas d'accès depuis Safeguard.
#      - upload impossible avec "scp.SCPException: scp: /local: Is a directory"
#      - lsof qui n'est pas installé sur la VM cible
#
# Todo:
#      - Fonction ssh_cmd à corriger pour retourner les 3 statuts de sortie des commandes ssh,
#      comme ssh_lsof_cmd. Les 2 fonctions pourront alors être réunies en une seule.


import time
import sys, os
import json
from subprocess import Popen, PIPE
sys.path.append(os.path.expanduser('../python-common')) # or give the full path

import paramiko
from paramiko import SSHClient
from scp import SCPClient

# Les fonctions suivantes ne sont pas disponibles publiquement.
## writeToFile: écrire dans un fichier
## search_in_file: rechercher dans un fichier
## chkAlivefping: la machine est-elle alive ?
## isOpen: le port est-il ouvert ?
## sgconn,sg_reqpwd,sg_checkIn,sg_checkOutPassword,assetPartitionList: obtenir le mdp de connexion à la machine
from myutils import writeToFile,search_in_file,chkAlivefping,isOpen
from sg import sgconn,sg_reqpwd,sg_checkIn,sg_checkOutPassword,assetPartitionList

def createSSHClient(user, pwd, host):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, 22, user, pwd)
    return client

def ssh_cmd(user, pwd, host, cmd):
    nbytes = 4096
    hostname = host
    port = 22
    username = user
    password = pwd
    command = cmd

    client = paramiko.Transport((hostname, port))
    client.connect(username=username, password=password)

    stdout_data = []
    stderr_data = []
    session = client.open_channel(kind='session')
    session.exec_command(command)
    while True:
        if session.recv_ready():
            stdout_data.append(session.recv(nbytes))
        if session.recv_stderr_ready():
            stderr_data.append(session.recv_stderr(nbytes))
        if session.exit_status_ready():
            break

    #print('exit status: ', session.recv_exit_status())
    #print('stdout: ' ,stdout_data)
    #print('error data: ', stderr_data)
    #return stdout_data
    return stderr_data

    session.close()
    client.close()

def ssh_lsof_cmd(user, pwd, host, cmd):
    nbytes = 4096
    hostname = host
    port = 22
    username = user
    password = pwd
    command = cmd

    client = paramiko.Transport((hostname, port))
    client.connect(username=username, password=password)

    stdout_data = []
    stderr_data = []
    session = client.open_channel(kind='session')
    session.exec_command(command)
    while True:
        if session.recv_ready():
            stdout_data.append(session.recv(nbytes))
        if session.recv_stderr_ready():
            stderr_data.append(session.recv_stderr(nbytes))
        if session.exit_status_ready():
            break

    #print('exit status: ', session.recv_exit_status())
    #print('stdout: ' ,stdout_data)
    #print('error data: ', stderr_data)
    return stdout_data, stderr_data, session.recv_exit_status()
    #return stderr_data

    session.close()
    client.close()

# MAIN()

# Obtenir un token du passwordvault
user_token = sgconn()
#print(user_token)

with open("inventaire.txt", "r") as file:
    for line in file:
        host = line.strip()
        print("----" + host + "----")
        # Vérifier si la machine n'est pas déjà traitée
        if not search_in_file(host,"done.txt"):
            # la machine est-elle reachable ?
            reachable = chkAlivefping(host)
            #print(reachable)
            if reachable:
                # test si le port WinRM est accessible
                if isOpen(host,22):
                    print("--- SSH port isOpen : --- " + host)
                    # obtenir le mdp root de la machine dans le passwordvault
                    requestId = sg_reqpwd(user_token, host,'root')
                    #print(requestId)
                    pwd = sg_checkOutPassword(user_token, requestId)
                    sg_checkIn(user_token, requestId)

                    # upload du bin log4shell dans /tmp
                    print("Upload en cours...")
                    ssh = createSSHClient('root', pwd, host)
                    scp = SCPClient(ssh.get_transport())
                    scp.put('log4shell', '/root/')

                    # lancer la commande de check avec sortie au format json
                    print("Scan en cours...")
                    # avec un renice si jamais
                    # out = ssh_cmd('root', pwd, host, '/usr/bin/nice -n -20 /local/log4shell --json scan /local /opt')
                    out = ssh_cmd('root', pwd, host, '/root/log4shell --json scan /local /opt')
                    #print(out)
                
                    for i in out:
                        writeToFile('scan.txt', host + ',')
                        #print(i.decode('utf-8'))
                        decoded_out = (i.decode('utf-8'))
                        print(decoded_out)
                        # on obtient un str donc passage en dict via json.loads pour pouvoir parser le json retouné par la commande
                        #if not decoded_out:
                        try:
                            json_out = json.loads(decoded_out)
                            #print(json_out['path'])
                            path = "empty"
                            versionInfo = "empty"
                            vulnerable = "empty"
                            # parcourir le DICT (la sortie json de la commande)
                            try:
                                fileName = json_out['fileName']
                                writeToFile('scan.txt', fileName + ',')
                            except KeyError:
                                print()
                                #print("La clé fileName n'existe pas.")
                            try:
                                path = json_out['path']
                                writeToFile('scan.txt', path + ',')
                                # si path n'est pas vide, check via lsof pour savoir si la lib est utilisée
                                if json_out['path']:
                                    
                                    print("path : " + json_out['path'])
                                    # log4shell détecte parfois un chemin avec ::, dans ce cas on ne peut pas 
                                    # tester avec lsof car le chemin est incorrect
                                    if "::" not in json_out['path']:
                                        commandelsof = "lsof " + json_out['path']
                                        lsof = ssh_lsof_cmd('root', pwd, host, commandelsof)
                                        print(lsof)

                                        for i in lsof[0]:
                                            print(i)
                                            # il nous faut un byte et non un str pour comparer
                                            if str.encode(json_out['path']) in i:
                                                print("contenu de i :")
                                                print(i)
                                                print("lib semble utilisée")
                                                libIsUsed=True
                                            # si la sortie de la commande est vide, la lib n'est pas utilisée
                                            if i == "":
                                                print("lib ne semble pas utilisée")
                                                libIsUsed=False
                                        # stderr_data est dans lsof[1] car c'est la seconde valeur retournée par la fonction ssh_lsof_cmd
                                        # si la sortie standard de la commande est vide, la lib n'est pas utilisée
                                        if not lsof[0]:
                                            print("lib ne semble pas utilisée")
                                            libIsUsed=False
                                        for i in lsof[1]:
                                            print(i)
                                            # il nous faut un byte et non un str pour comparer
                                            if b'No such file or directory' in i:
                                                print("lib ne semble pas utilisée")
                                                libIsUsed=False

                            except KeyError:
                                print()
                                #print("La clé path n'existe pas.")
                            try:
                                versionInfo = json_out['versionInfo']
                                writeToFile('scan.txt', versionInfo + ',')
                            except KeyError:
                                print()
                                #print("La clé versionInfo n'existe pas.")
                            try:
                                vulnerable = json_out['message']
                                writeToFile('scan.txt', vulnerable + ',')
                            except KeyError:
                                print()
                                #print("La clé message n'existe pas.")
                            try:
                                if libIsUsed == True:
                                    writeToFile('scan.txt', 'lib semble utilisée' + ',')
                                elif libIsUsed == False:
                                    writeToFile('scan.txt', 'lib ne semble pas utilisée' + ',')
                                else:
                                    writeToFile('scan.txt', 'status usage de la lib inconnu' + ',')
                            except:
                                writeToFile('scan.txt', 'status usage de la lib inconnu' + ',')
                        
                            # si la lib est utilisée, vérifier si le correctif Dlog4j2.formatMsgNoLookups=true est appliqué
                            if libIsUsed == True:
                                # vérification du correctif Dlog4j2.formatMsgNoLookups=true
                                try:
                                    # obtenir le PID des processus qui utilisent la lib située à ce chemin
                                    javapid_command = 'lsof -t ' + json_out['path']
                                    javapid = ssh_lsof_cmd('root', pwd, host, javapid_command)
                                    # si la liste javapid[0] n'est pas vide
                                    #print("javapid :")
                                    #print(javapid)
                                    if javapid[0]:
                                        # pour chaque PID trouvé par "lsof -t" (javapid[0] contient une list)
                                        for j in javapid[0]:
                                            #print("contenu de j :")
                                            #print(j)
                                            try:
                                                pid = j.decode('utf-8')
                                                commande_javaps = 'ps -ef | grep -v "bash -c ps -ef" | grep Dlog4j2.formatMsgNoLookups=true | grep ' + pid
                                                javaps = ssh_lsof_cmd('root', pwd, host, commande_javaps)
                                                #print("javaps")
                                                #print(javaps)
                                                #print("javaps[0]")
                                                #print(javaps[0])
                                                # si la sortie de la commande est vide, le correctif n'est pas alliqué
                                                if javaps[0]:
                                                    print("CORRECTIF : Dlog4j2.formatMsgNoLookups=true appliqué")
                                                    MsgNoLookupsApplied=True
                                                elif not javaps[0]:
                                                    print("CORRECTIF : Dlog4j2.formatMsgNoLookups=true *NON* appliqué")
                                                    MsgNoLookupsApplied=False
                                                if javaps[1]:
                                                    print("Erreur execution : " + commande_javaps)
                                                    #print(javaps[1])
                                                    MsgNoLookupsApplied=False
                                            except:
                                                print("Erreur execution : " + commande_javaps)
                                                MsgNoLookupsApplied=False
                                except:
                                    print("Erreur execution : " + javapid_command)  
                                    MsgNoLookupsApplied=False

                            try:
                                if MsgNoLookupsApplied == True:
                                    writeToFile('scan.txt', '(ALPHA) Correctif Dlog4j2.formatMsgNoLookups=true appliqué' + '\n')
                                elif MsgNoLookupsApplied == False:
                                    writeToFile('scan.txt', '(ALPHA) Correctif Dlog4j2.formatMsgNoLookups=true NON appliqué' + '\n')
                            except:
                                writeToFile('scan.txt', '\n')
                        
                        except ValueError:  # includes simplejson.decoder.JSONDecodeError
                            print('Decoding JSON has failed')
                            #writeToFile('scan.txt', 'Erreur de scan\n')
                            writeToFile('scan.txt', '\n')
                        print()
                        print('---')
                    writeToFile('done.txt',host + '\n')
                    print("Suppression de /root/log4shell")
                    out = ssh_cmd('root', pwd, host, 'rm /root/log4shell')
                    print("--- Fin " + host + " ---")
            else:
                print(host + " not reachable.")        
        else:
            print(host + " déjà traité.")
        #input("Press Enter to continue...")