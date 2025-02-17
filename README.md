# **Python4SRC2 - Gestion des Services via SSH**

Ce projet Python permet de gérer à distance l'installation, la configuration, et la maintenance de services sur une machine Linux via SSH. Il offre une interface en ligne de commande permettant de piloter :

- La gestion classique de paquets (installation, suppression, mise à jour, vérification)
- La configuration et la gestion de sites web (Apache2 + PHP)
- La gestion d'un serveur FTP (vsftpd)
- L'installation et la configuration d'OpenLDAP (gestion d'utilisateurs LDAP et organisationnel)
- La gestion des utilisateurs Linux (création, suppression, changement de mot de passe, gestion des groupes)
- La configuration des interfaces réseau et des serveurs DNS

---

## **1. Prérequis**

### a) Environnement et dépendances
- **Python 3** doit être installé sur la machine locale.
- Dépendances Python :
  - [paramiko](https://www.paramiko.org/) pour la connexion SSH.
  - Pour installer ce module, lancez :
    ```bash
    pip install paramiko
    ```

### b) Machine distante
- Une distribution Linux (Debian/Ubuntu ou similaire) disposant d'un service SSH actif.
- Des droits sudo pour l'exécution de commandes administratives (requis pour plusieurs fonctionnalités).

---

## **2. Structure du Projet**

```
Python4SRC2/
├── main.py                # Interface et menus interactifs de l'application.
├── sshpackagemanager.py   # Classes de gestion SSH dédiées aux paquets, Apache, FTP, LDAP, utilisateurs et réseau.
├── colored_formatter.py   # Formatter de log personnalisé avec couleurs.
├── README.md              # Cette documentation.
```

---

## **3. Installation et Configuration**

1. **Cloner le dépôt GitHub :**
   ```bash
   git clone https://github.com/VotreCompte/Python4SRC2.git
   cd Python4SRC2
   ```

2. **Installer les dépendances :**
   ```bash
   pip install paramiko
   ```

3. **(Optionnel) Configuration sudoers :**  
   Pour éviter de demander le mot de passe pour certaines commandes, éditez le fichier sudoers :
   ```bash
   sudo visudo
   ```
   Ajoutez par exemple :
   ```bash
   Cmnd_Alias APACHE_CONF = /usr/bin/cat /etc/apache2/sites-available/*.conf
   user ALL=(ALL) NOPASSWD: APACHE_CONF
   ```

---

## **4. Utilisation**

1. **Lancer le script principal :**
   ```bash
   python main.py
   ```

2. **Au démarrage, entrez l'adresse IP ou le nom d'hôte de la machine distante, puis vos identifiants SSH.**
3. **Naviguez ensuite dans le menu principal qui présente plusieurs sous-menus dédiés :**
   - **Gestion des paquets classiques** pour installer, désinstaller, mettre à jour ou vérifier un paquet.
   - **Gestion web (Apache2 + PHP)** pour installer et configurer des sites web.
   - **Gestion du serveur FTP** pour configurer vsftpd.
   - **Gestion du serveur LDAP** pour installer, reconfigurer et administrer OpenLDAP.
   - **Gestion des utilisateurs Linux** pour créer, modifier ou supprimer des comptes utilisateurs.
   - **Gestion du réseau et DNS** pour configurer les interfaces réseau et paramétrer des serveurs DNS.

---

## **5. Fonctionnalités en Détail**

### a) Gestion des paquets classiques
- **Installation / Mise à jour / Désinstallation**  
  Utilise `apt-get` pour manipuler les paquets.  
  Exemple de commandes exécutées :
  - `sudo apt-get install -y <paquet>`
  - `sudo apt-get remove -y <paquet>`
  - `dpkg -l | grep <paquet>`

### b) Serveur Web (Apache2 + PHP)
- **Installation d'Apache2 et PHP**  
  Création de répertoires personnalisés dans `/var/www/html/` et configuration d’un fichier de site dans `/etc/apache2/sites-available/`.
- **Activation / désactivation et rechargement du service Apache**.

### c) Serveur FTP (vsftpd)
- **Configuration de vsftpd**  
  Mise à jour des paramètres tels que `anonymous_enable`, `local_enable` et `write_enable`.
- **Redémarrage du service vsftpd.**

### d) Serveur LDAP (OpenLDAP)
- **Installation et configuration automatisée** via un script Bash généré temporairement.
- **Ajout / Suppression d’utilisateurs LDAP et d’Unités Organisationnelles (OU).**

### e) Gestion des Utilisateurs Linux
- **Création d’utilisateur avec home directory**
  ```bash
  sudo useradd -m <nom_utilisateur>
  ```
- **Modification de mot de passe :**
  ```bash
  echo '<nom_utilisateur>:<mot_de_passe>' | sudo chpasswd
  ```
- **Liste des utilisateurs et groupes.**

### f) Configuration Réseau et DNS
- **Affichage et configuration des interfaces réseau** (activation, désactivation, IP statique ou DHCP).
- **Configuration des serveurs DNS** via modification du fichier `/etc/resolv.conf`.

---

## **6. Sécurité**

- **Privilèges restreints :**  
  Configurez correctement les accès sudo pour limiter les commandes disponibles selon l'utilisateur.
- **Connexion SSH :**  
  Assurez-vous que seuls les utilisateurs autorisés puissent se connecter à la machine distante.

---

## **7. Dépannage**

- **Échec de la connexion SSH :**  
  Vérifiez l'adresse, les identifiants et que le service SSH est bien actif sur la machine distante.
- **Erreur sur les commandes sudo :**  
  Assurez-vous que les règles dans `/etc/sudoers` sont correctement configurées.
- **Dépendances manquantes :**  
  Installez le module requis tel que `paramiko`.

---

## **8. Contribution**

Les contributions sont les bienvenues !  
- **Pull Requests** : N’hésitez pas à proposer des améliorations via des pull requests.
- **Issues** : Signalez les problèmes ou les bugs dans la section [Issues](https://github.com/VotreCompte/Python4SRC2/issues).

---

## **9. Licence**

Ce projet est sous licence MIT.  
Voir le fichier [LICENSE](LICENSE) pour plus de détails.