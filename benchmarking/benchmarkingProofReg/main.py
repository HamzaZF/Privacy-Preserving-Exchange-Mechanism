import os
import re
import subprocess
import sys
import time

def remove_ansi_escape_sequences(text):
    """
    Remove ANSI escape sequences from the given text.
    """
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def extract_prover_time(output):
    """
    Extract the prover time from the command output.
    """
    lines = (output.split('\n')[4].split('='))

    return float(remove_ansi_escape_sequences(lines[5]))

def extract_verification_time(output):
    """
    Extract the verification time from the command output.
    """
    lines = (output.split('\n')[5].split('='))

    return float(remove_ansi_escape_sequences(lines[3]))

def run_go_command_in_subfolders(base_dir):
    folder_paths = ["./ProofReg"]
    index = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160]
    # Liste pour stocker les temps d'exécution
    execution_times = []
    prover_times = []
    verification_times = []

    g = 0
    
    for i in index:
        g+=1
        # Parcours des sous-dossiers
        print(f"Exécution dans le dossier: {folder_paths[0]}")
                
        # Enregistrer le temps de début
        start_time = time.time()
                
        # Exécuter la commande go run main.go
        result = subprocess.run(['go', 'run', 'main.go'], cwd=folder_paths[0], capture_output=True, text=True)
                
        # Enregistrer le temps de fin
        end_time = time.time()
                
        # Calculer le temps d'exécution
        execution_time = end_time - start_time
                
        # Afficher la sortie de la commande
        #print(result.stdout)
        #print(result.stderr, file=sys.stderr)
                
        # Ajouter le temps d'exécution à la liste
        execution_times.append(execution_time)

        # Extraire le temps de génération de la preuve
        tps = extract_prover_time(result.stdout)
        tps_verification = extract_verification_time(result.stdout)
            
        if tps is not None:
            prover_times.append(tps)
            print(f"Temps de génération de la preuve: {tps:.2f} ms")
        else:
            print("Temps de génération de la preuve non trouvé.")

        if tps_verification is not None:
            verification_times.append(tps_verification)
            print(f"Temps de vérification de la preuve: {tps_verification:.2f} ms")
        else:
            print("Temps de vérification de la preuve non trouvé.")

        

        

    return [index, prover_times, verification_times]

if __name__ == "__main__":
    base_directory = '.'  # Répertoire de base à partir duquel commencer la recherche
    res = run_go_command_in_subfolders(base_directory)

    print("index", res[0])
    print("prover_times", res[1])
    print("verification_times", res[2])

