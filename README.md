# 🗳️ Système de Vote Sécurisé avec DSA/ElGamal et ECC

Ce projet implémente un **système de vote électronique sécurisé** utilisant des **algorithmes de cryptographie** comme :
- **DSA (Digital Signature Algorithm)**
- **ElGamal (chiffrement et signature)**
- **Elliptic Curve Cryptography (ECC)** pour plus d'efficacité

Il repose sur une **architecture client-serveur** permettant :
- 📥 **Enregistrement sécurisé des clés publiques des électeurs**
- 🔒 **Chiffrement et signature des votes**
- ✅ **Validation des votes sur le serveur**
- 🏆 **Décompte et annonce du candidat gagnant**
- 📴 **Arrêt automatique du serveur après 10 votes**

---

## 📌 Structure du projet

```
crypto/
│── Makefile            # Commandes pour exécuter le serveur et le client
│── README.md           # Documentation du projet
│── algebra.py          # Implémentation des opérations mathématiques
│── client.py           # Code du client (envoi de clé, chiffrement, vote)
│── server.py           # Code du serveur (gestion des votes, comptage, arrêt)
│── dsa.py              # Implémentation du DSA (Digital Signature Algorithm)
│── ecdsa.py            # Implémentation de l'ECDSA (Elliptic Curve DSA)
│── ecelgamal.py        # Implémentation d'ElGamal sur courbes elliptiques
│── elgamal.py          # Implémentation du chiffrement ElGamal classique
│── rfc7748.py          # Algorithmes liés aux courbes elliptiques (RFC 7748)
│── run_tests.py        # Script pour exécuter les tests
│── dependencies/       # Bibliothèques cryptographiques utilisées
│── tests/              # Fichiers de tests pour valider les algorithmes
```

---

## 🚀 Installation et Exécution

### 📥 1. Prérequis
- **Python 3.8+**
- **Aucune Bibliothèques requises** (présente dans le projet)

---

### 🖥️ 2. Lancer le serveur

```bash
python3 server.py
```
- L’interface vous demandera d’utiliser **DSA/ElGamal classique ou ECC** :
  ```
  Utiliser DSA et ElGamal sur courbes elliptiques ? (Y/N)
  ```
- Le serveur démarrera et affichera les requêtes des clients.

---

### 👤 3. Lancer le client et voter

Dans un autre terminal :

```bash
python3 client.py
```

- Le client :
  1. Génère et envoie une **clé publique** au serveur.
  2. Demande à l'utilisateur **pour quel candidat voter** :
     ```
     🗳️  Pour quel candidat votez-vous ? (1-5) :
     ```
  3. Chiffre et signe le vote.
  4. Envoie le vote au serveur.

---

### 🏆 4. Résultats et arrêt du serveur

- Après **10 votes enregistrés**, le serveur :
  - Déchiffre et compte les votes.
  - Affiche le **candidat gagnant**.

Exemple de sortie :

```
============================================================
🏆 Le candidat 3 a gagné l'élection avec 5 votes !
📴 Arrêt du serveur après 10 votes
✅ Serveur arrêté proprement.
```

---

## 🔐 Sécurité du système

✅ **Chiffrement des votes** via **ElGamal / ECC**  
✅ **Signature numérique** des votes via **DSA / ECDSA**  
✅ **Validation des signatures avant enregistrement**  
✅ **Protocole sécurisé de transmission des votes**  
✅ **Résultats non modifiables sans décryptage**  

---

## 🛠 Développement & Test

### 🔹 Tester le code

Pour exécuter les tests de validation des algorithmes :

```bash
python3 run_tests.py || make test
```

### 🔹 Exécuter avec `make`

Un **Makefile** est fourni pour simplifier l'exécution :

```bash
make               # Démarre le serveur
make client        # Démarre un client pour voter
```

## 📧 Auteurs
 
- **Jebril HOCINE**
- **Paul FERREIRA**
- **Erwan KERMARREC**

---

