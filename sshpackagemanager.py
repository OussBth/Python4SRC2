import paramiko
import os
import tempfile

class SSHPackageManager:
    """
    Classe de base qui gère la connexion SSH et propose des méthodes
    générales pour installer, supprimer, mettre à jour, vérifier des paquets.
    """

    def __init__(self, hostname, username, password):
        # On stocke les informations de connexion (hôte, user, mdp)
        self.hostname = hostname
        self.username = username
        self.password = password

        # On crée un client SSH Paramiko
        self.client = paramiko.SSHClient()
        # On autorise l'ajout automatique de la clé de l'hôte distant
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # On se connecte à la machine distante
        self.client.connect(hostname, username=username, password=password)

    def execute_command(self, command):
        """
        Méthode utilitaire pour exécuter une commande sur la machine distante.
        On force un environnement non-interactif (DEBIAN_FRONTEND=noninteractive).
        """
        command = f"export TERM=xterm DEBIAN_FRONTEND=noninteractive && {command}"
        stdin, stdout, stderr = self.client.exec_command(command)
        # On récupère la sortie standard et la sortie d'erreur
        return stdout.read().decode(), stderr.read().decode()

    def install_single_package(self, package):
        """
        Installe un seul paquet (apt-get install -y <package>).
        """
        print(f"[INFO] Installation du paquet {package}...")
        output, error = self.execute_command(f"sudo apt-get install -y {package}")
        if error.strip():
            print(f"[ERREUR] lors de l'installation de {package} : {error}")
        else:
            print(output)

    def install_packages(self, package_name):
        """
        Installe plusieurs paquets à la fois (séparés par un espace).
        1) apt-get update
        2) apt-get install pour chaque paquet
        """
        packages = package_name.split()

        # Mise à jour de la liste des paquets
        output, error = self.execute_command("sudo apt-get update")
        if error.strip():
            print(f"[ERREUR] lors du apt-get update : {error}")
        else:
            print(output)

        # Installation de chaque paquet
        for package in packages:
            self.install_single_package(package)

    def remove_package(self, package_name):
        """
        Supprime un paquet (apt-get remove -y)
        puis on exécute apt-get autoremove -y pour nettoyer.
        """
        print(f"[INFO] Suppression du paquet {package_name}...")
        output, error = self.execute_command(f"sudo apt-get remove -y {package_name}")
        if error.strip():
            print(f"[ERREUR] lors de la suppression de {package_name} : {error}")
        else:
            print(output)
            # Nettoyage
            self.execute_command("sudo apt-get autoremove -y")

    def verify_package(self, package_name):
        """
        Vérifie si un paquet est installé (dpkg -l | grep <package>).
        """
        print(f"[INFO] Vérification de l'installation de {package_name} avec dpkg...")
        output, error = self.execute_command(f"dpkg -l | grep {package_name}")
        if output.strip():
            print(f"[OK] Le paquet {package_name} est installé.")
            return True
        else:
            print(f"[INFO] Le paquet {package_name} n'est pas installé.")
            return False

    def update_package(self, package_name):
        """
        Met à jour un paquet s'il est déjà installé.
        Sinon, indique qu'il n'est pas installé.
        """
        if self.verify_package(package_name):
            print(f"[INFO] Mise à jour du paquet {package_name}...")
            output, error = self.execute_command(
                f"sudo apt-get update && sudo apt-get install --only-upgrade -y {package_name}"
            )
            if error.strip():
                print(f"[ERREUR] lors de la mise à jour de {package_name}: {error}")
            else:
                print(output)
        else:
            print(f"[INFO] Le paquet {package_name} n'est pas installé, aucune mise à jour nécessaire.")

    def close_connection(self):
        """
        Ferme la connexion SSH proprement.
        """
        self.client.close()
        print("[INFO] Connexion SSH fermée.")


class WebManager(SSHPackageManager):
    """
    Gère les actions spécifiques au serveur web (Apache2).
    Hérite de SSHPackageManager pour la connexion SSH et l'exécution de commandes.
    """

    def configure_apache2(self, site_name, port=80):
        """
        Crée un répertoire pour le site, génère un fichier de config .conf,
        active le site et recharge Apache.
        """
        print("[INFO] Configuration du service Apache2...")
        commandes = [
            f"sudo mkdir -p /var/www/html/{site_name}",
            f"echo '<h1>Bienvenue sur le site {site_name}</h1>' | sudo tee /var/www/html/{site_name}/index.html",
            (
                "sudo bash -c 'cat > /etc/apache2/sites-available/"
                f"{site_name}.conf <<EOF\n"
                f"<VirtualHost *:{port}>\n"
                f"    ServerAdmin webmaster@localhost\n"
                f"    DocumentRoot /var/www/html/{site_name}\n"
                f"    ErrorLog ${{APACHE_LOG_DIR}}/error.log\n"
                f"    CustomLog ${{APACHE_LOG_DIR}}/access.log combined\n"
                f"</VirtualHost>\n"
                f"EOF'"
            ),
            f"sudo a2ensite {site_name}",
            "sudo systemctl reload apache2"
        ]

        for cmd in commandes:
            output, error = self.execute_command(cmd)
            if error.strip():
                print(f"[ERREUR] : {error}")
            else:
                print(output)

    def list_apache_sites(self):
        """
        Liste les fichiers .conf dans /etc/apache2/sites-available
        pour déterminer les sites existants.
        """
        print("[INFO] Récupération des sites Apache disponibles...")
        output, error = self.execute_command("ls /etc/apache2/sites-available | grep '.conf'")
        if error.strip():
            print(f"[ERREUR] : {error}")
            return []
        else:
            sites = [line.replace('.conf', '') for line in output.splitlines()]
            return sites

    def print_web_configuration(self, site_name):
        """
        Affiche le contenu du fichier de configuration du site <site_name>.
        """
        print(f"[INFO] Affichage de la configuration pour le site : {site_name}")
        output, error = self.execute_command(f"sudo /bin/cat /etc/apache2/sites-available/{site_name}.conf")
        if error.strip():
            print(f"[ERREUR] : {error}")
        else:
            print(output)

    def delete_apache_site(self, site_name):
        """
        Désactive le site, supprime le fichier .conf et le dossier du site,
        puis recharge Apache.
        """
        print(f"[INFO] Suppression du site Apache : {site_name}...")
        commandes = [
            f"sudo a2dissite {site_name}",
            f"sudo rm -f /etc/apache2/sites-available/{site_name}.conf",
            f"sudo rm -rf /var/www/html/{site_name}",
            "sudo systemctl reload apache2"
        ]
        for cmd in commandes:
            output, error = self.execute_command(cmd)
            if error.strip():
                print(f"[ERREUR] lors de l'exécution de la commande : {cmd}\n{error}")
            else:
                print(output)


class FTPManager(SSHPackageManager):
    """
    Gère la configuration du serveur FTP (vsftpd).
    """

    def configure_vsftpd(self, anonymous_enable, local_enable, write_enable):
        """
        Sauvegarde le fichier /etc/vsftpd.conf, puis modifie les lignes
        anonymous_enable / local_enable / write_enable (même si elles sont commentées).
        Ensuite redémarre vsftpd.
        """
        print("[INFO] Configuration de vsftpd...")
        commandes = [
            "sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak",
            f"sudo sed -i 's/^#\\?anonymous_enable=.*/anonymous_enable={anonymous_enable.upper()}/' /etc/vsftpd.conf",
            f"sudo sed -i 's/^#\\?local_enable=.*/local_enable={local_enable.upper()}/' /etc/vsftpd.conf",
            f"sudo sed -i 's/^#\\?write_enable=.*/write_enable={write_enable.upper()}/' /etc/vsftpd.conf",
            "sudo systemctl restart vsftpd"
        ]

        for cmd in commandes:
            output, error = self.execute_command(cmd)
            if error.strip():
                print(f"[ERREUR] : {error}")
            else:
                print(output)

    def print_ftp_configuration(self):
        """
        Affiche les lignes qui correspondent à (anonymous_enable|local_enable|write_enable)
        dans /etc/vsftpd.conf pour vérifier la config actuelle.
        """
        print("[INFO] Affichage des lignes modifiées dans la configuration FTP...")
        output, error = self.execute_command("sudo /usr/bin/grep -E '^(anonymous_enable|local_enable|write_enable)' /etc/vsftpd.conf")
        if error.strip():
            print(f"[ERREUR] : {error}")
        else:
            print(output)

###TRAITEMENT LDAP

def domain_to_dn(domain: str) -> str:
    """
    Convertit un domaine style 'example.com'
    en 'dc=example,dc=com'.
    """
    parts = domain.split('.')
    dn_parts = [f"dc={p}" for p in parts]
    return ",".join(dn_parts)



class LDAPManager(SSHPackageManager):
    """
    Gère l'installation, la configuration, la purge d'OpenLDAP,
    ainsi que l'ajout et la liste d'utilisateurs dans l'annuaire.
    """



    def install_and_configure_ldap_via_script(self, domain, org_name, admin_password):
        """
        Génère un script Bash complet pour installer et configurer OpenLDAP
        en non-interactif, puis l'envoie et l'exécute sur la machine distante.
        'domain' est un string type 'example.com'.
        """

        script_content = f"""#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== Script d'installation et de configuration OpenLDAP ==="
echo "Domaine LDAP : {domain}"
echo "Organisation : {org_name}"
echo "Mot de passe Admin : {admin_password}"

# Debconf selections
sudo debconf-set-selections <<< 'slapd slapd/no_configuration boolean false'
sudo debconf-set-selections <<< 'slapd slapd/internal/adminpw password {admin_password}'
sudo debconf-set-selections <<< 'slapd slapd/internal/generated_adminpw password {admin_password}'

sudo debconf-set-selections <<< 'slapd slapd/password1 password {admin_password}'
sudo debconf-set-selections <<< 'slapd slapd/password2 password {admin_password}'
sudo debconf-set-selections <<< 'slapd slapd/domain string {domain}'
sudo debconf-set-selections <<< 'slapd shared/organization string {org_name}'
sudo debconf-set-selections <<< 'slapd slapd/backend select mdb'
sudo debconf-set-selections <<< 'slapd slapd/purge_database boolean true'
sudo debconf-set-selections <<< 'slapd slapd/move_old_database boolean true'
sudo debconf-set-selections <<< 'slapd slapd/allow_ldap_v2 boolean false'

# Installation
sudo apt-get update
sudo apt-get install -y slapd ldap-utils

# Éventuellement reconfigurer si besoin
# sudo dpkg-reconfigure -f noninteractive slapd

echo "=== Fin du script d'installation OpenLDAP ==="
"""

        # 1) Écriture locale d'un script .sh temporaire
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.sh') as tmpfile:
            tmpfile.write(script_content)
            local_script_path = tmpfile.name

        print(f"[INFO] Script Bash créé localement : {local_script_path}")

        # 2) Copie du script vers la machine distante
        remote_script_path = "/tmp/config_openldap.sh"
        sftp = self.client.open_sftp()
        sftp.put(local_script_path, remote_script_path)
        sftp.close()

        # 3) Exécution sur la machine distante
        self.execute_command(f"sudo chmod +x {remote_script_path}")
        self.execute_command(f"sudo dos2unix {remote_script_path}")

        self.execute_command(f"ls -l {remote_script_path}")
        self.execute_command("ls -l /tmp")

        output, error = self.execute_command(f"sudo /bin/bash {remote_script_path}")
        if error.strip():
            print(f"[ERREUR] lors de l'exécution du script : {error}")
        else:
            print(output)

        # Nettoyage du script local
        os.remove(local_script_path)

        print("[INFO] Script d'installation LDAP exécuté avec succès (ou erreurs signalées ci-dessus).")


    def configure_ldap(self, domain, org_name, admin_password):
        """
        Reconfigure slapd en mode non interactif
        (changements de domaine/organisation/mot de passe).
        'domain' est un string type 'example.com'.
        """
        print("[INFO] Configuration d'OpenLDAP via dpkg-reconfigure (non-interactive).")

        debconf_cmds = [
            f"sudo debconf-set-selections <<< 'slapd slapd/password1 password {admin_password}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/password2 password {admin_password}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/domain string {domain}'",
            f"sudo debconf-set-selections <<< 'slapd shared/organization string {org_name}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/backend select mdb'",
            f"sudo debconf-set-selections <<< 'slapd slapd/purge_database boolean true'",
            f"sudo debconf-set-selections <<< 'slapd slapd/move_old_database boolean true'",
            f"sudo debconf-set-selections <<< 'slapd slapd/allow_ldap_v2 boolean false'"
        ]

        for cmd in debconf_cmds:
            self.execute_command(cmd)

        reconfigure_output, reconfigure_err = self.execute_command(
            "sudo dpkg-reconfigure -f noninteractive slapd"
        )
        if reconfigure_err.strip():
            print(f"[ERREUR] lors de la configuration : {reconfigure_err}")
        else:
            print(reconfigure_output)


    def add_ldap_user(self, user_cn, domain):
        """
        Ajoute un utilisateur simple (inetOrgPerson).
        L'utilisateur saisit 'example.com', qu'on convertit en 'dc=example,dc=com'.
        """
        base_dn = domain_to_dn(domain)  # ex: "dc=example,dc=com"
        print(f"[INFO] Ajout de l'utilisateur {user_cn} dans {base_dn}...")

        ldif_content = f"""
dn: cn={user_cn},ou=People,{base_dn}
objectClass: inetOrgPerson
sn: {user_cn}
cn: {user_cn}
userPassword: secret
"""
        tmp_ldif_path = f"/tmp/{user_cn}.ldif"
        self.execute_command(f"echo \"{ldif_content}\" > {tmp_ldif_path}")

        output, error = self.execute_command(
            f"sudo ldapadd -x -D 'cn=admin,{base_dn}' -w admin -f {tmp_ldif_path}"
        )
        if error.strip():
            print(f"[ERREUR] lors de l'ajout de l'utilisateur LDAP '{user_cn}' : {error}")
        else:
            print(output)


    def list_ldap_users(self, domain="example.com"):
        """
        Liste les utilisateurs présents dans 'ou=People,dc=example,dc=com'.
        """
        base_dn = domain_to_dn(domain)
        print(f"[INFO] Listing des utilisateurs sous 'ou=People,{base_dn}'...")

        output, error = self.execute_command(
            f"ldapsearch -x -LLL -b 'ou=People,{base_dn}' cn"
        )
        if error.strip():
            print(f"[ERREUR] lors du listing des utilisateurs : {error}")
        else:
            print(output)


    def remove_ldap_config(self):
        """
        Supprime la configuration OpenLDAP (slapd) de la machine distante :
        1) apt-get remove --purge -y slapd
        2) rm -rf /etc/ldap/slapd.d /var/lib/ldap
        3) (optionnel) apt-get autoremove -y
        """
        print("[INFO] Suppression/Purge de la configuration OpenLDAP...")

        # 1) Purge du paquet slapd
        output, error = self.execute_command("sudo apt-get remove --purge -y slapd")
        if error.strip():
            print(f"[ERREUR] lors de la purge du paquet slapd : {error}")
        else:
            print(output)

        # 2) Nettoyage des dossiers
        # on supprime /etc/ldap/slapd.d et /var/lib/ldap
        output, error = self.execute_command("sudo rm -rf /etc/ldap/slapd.d /var/lib/ldap")
        if error.strip():
            print(f"[ERREUR] lors du nettoyage /etc/ldap/slapd.d et /var/lib/ldap : {error}")
        else:
            print(output)

        # 3) (Optionnel) apt-get autoremove
        output, error = self.execute_command("sudo apt-get autoremove -y")
        if error.strip():
            print(f"[ERREUR] lors du autoremove : {error}")
        else:
            print(output)

        print("[INFO] Configuration OpenLDAP supprimée (purge) avec succès.")

class LinuxUserManager(SSHPackageManager):
    """
    Gère la création, suppression, modification de mot de passe
    et la liste des groupes utilisateurs sous Linux.
    """

    def create_user(self, username, password):
        print(f"[INFO] Création de l'utilisateur {username}.")
        # On vérifie si l'utilisateur existe déjà (id -u <username>)
        output, error = self.execute_command(f"id -u {username}")
        if "no such user" not in error.strip() and output.strip():
            print(f"[WARNING] L'utilisateur {username} existe déjà.")
            return

        # Création de l'utilisateur avec home directory (-m)
        create_out, create_err = self.execute_command(f"sudo useradd -m {username}")
        if create_err.strip():
            print(f"[ERREUR] Impossible de créer l'utilisateur : {create_err}")
            return
        else:
            print(create_out)

        # On définit le mot de passe via chpasswd
        output, error = self.execute_command(f"echo '{username}:{password}' | sudo chpasswd")
        if error.strip():
            print(f"[ERREUR] Impossible de changer le mot de passe : {error}")
        else:
            print("[INFO] Mot de passe défini avec succès.")

    def delete_user(self, username):
        print(f"[INFO] Suppression de l'utilisateur {username}.")
        output, error = self.execute_command(f"id -u {username}")
        if "no such user" in error.strip():
            print(f"[WARNING] L'utilisateur {username} n'existe pas.")
            return

        output, error = self.execute_command(f"sudo userdel -r {username}")
        if error.strip():
            print(f"[ERREUR] lors de la suppression de l'utilisateur : {error}")
        else:
            print(output)

    def change_password(self, username, new_password):
        print(f"[INFO] Changement du mot de passe de {username}.")
        output, error = self.execute_command(f"id -u {username}")
        if "no such user" in error.strip():
            print(f"[WARNING] L'utilisateur {username} n'existe pas.")
            return

        output, error = self.execute_command(f"echo '{username}:{new_password}' | sudo chpasswd")
        if error.strip():
            print(f"[ERREUR] Impossible de changer le mot de passe : {error}")
        else:
            print("[INFO] Mot de passe modifié avec succès.")

    def add_group(self, username, group_name):
        print(f"[INFO] Ajout des groupes pour l'utilisateur {username}.")
        output, error = self.execute_command(f"sudo groupadd {username} {group_name}")
        if error.strip():
            print(f"[ERREUR] Impossible d'ajouter le groupe : {error}")
        else:
            print("[INFO] Groupe ajouté avec succès")


    def list_groups(self, username):
        """
        Si un username est fourni, on liste ses groupes (id -nG <username>).
        Sinon, on liste tous les groupes (cut -d: -f1 /etc/group).
        """
        if username:
            print(f"[INFO] Groupes de {username} :")
            output, error = self.execute_command(f"id -nG {username}")
            if error.strip():
                print(f"[ERREUR] : {error}")
            else:
                print(output)
        else:
            print("[INFO] Liste de tous les groupes :")
            output, error = self.execute_command("cut -d: -f1 /etc/group")
            if error.strip():
                print(f"[ERREUR] : {error}")
            else:
                print(output)

    def list_users(self):
        """
        On liste tout les utilisateurs (cut -d: -f1 /etc/user).
        """

        print("[INFO] Liste des utilisateurs :")
        output, error = self.execute_command("id -u")
        if error.strip():
            print(f"[ERREUR] : {error}")
        else:
            print(output)


class NetworkManager(SSHPackageManager):
    """
    Gère les configurations réseau et le DNS de la machine distante.
    """

    def list_interfaces(self):
        """
        Liste les interfaces réseau disponibles.
        """
        print("[INFO] Récupération des interfaces réseau...")
        command = "ip link show"
        output, error = self.execute_command(command)
        if error.strip():
            print(f"[ERREUR] lors de la récupération des interfaces : {error}")
        else:
            print(output)

    def get_interface_status(self, interface):
        """
        Affiche l'état et la configuration de l'interface spécifiée.
        """
        print(f"[INFO] Récupération de l'état de l'interface {interface}...")
        command = f"ip addr show {interface}"
        output, error = self.execute_command(command)
        if error.strip():
            print(f"[ERREUR] lors de la récupération de l'état de {interface} : {error}")
        else:
            print(output)

    def enable_interface(self, interface):
        """
        Active l'interface réseau spécifiée.
        """
        print(f"[INFO] Activation de l'interface {interface}...")
        command = f"sudo ip link set {interface} up"
        output, error = self.execute_command(command)
        if error.strip():
            print(f"[ERREUR] lors de l'activation de {interface} : {error}")
        else:
            print(f"[INFO] Interface {interface} activée.")

    def disable_interface(self, interface):
        """
        Désactive l'interface réseau spécifiée.
        """
        print(f"[INFO] Désactivation de l'interface {interface}...")
        command = f"sudo ip link set {interface} down"
        output, error = self.execute_command(command)
        if error.strip():
            print(f"[ERREUR] lors de la désactivation de {interface} : {error}")
        else:
            print(f"[INFO] Interface {interface} désactivée.")

    def configure_static_ip(self, interface, ip, netmask, gateway):
        """
        Configure une adresse IP statique sur l'interface.
        Remarque : la conversion du netmask (ex: 255.255.255.0) en préfixe CIDR est gérée par une méthode utilitaire.
        """
        print(f"[INFO] Configuration de l'IP statique sur {interface}...")
        # Supprime d'abord toute configuration IP existante sur l'interface
        self.execute_command(f"sudo ip addr flush dev {interface}")

        prefix = self.netmask_to_prefix(netmask)
        # Ajoute la nouvelle IP
        command = f"sudo ip addr add {ip}/{prefix} dev {interface}"
        output, error = self.execute_command(command)
        if error.strip():
            print(f"[ERREUR] lors de la configuration de l'IP sur {interface} : {error}")
        else:
            print(f"[INFO] {interface} configurée avec l'IP {ip}/{prefix}.")

        # Configure la route par défaut via le gateway
        output, error = self.execute_command(f"sudo ip route add default via {gateway} dev {interface}")
        if error.strip():
            print(f"[ERREUR] lors de la configuration de la route par défaut : {error}")
        else:
            print(f"[INFO] Route par défaut configurée via {gateway}.")

    def netmask_to_prefix(self, netmask):
        """
        Convertit un netmask (ex: 255.255.255.0) en préfixe CIDR (ex: 24).
        """
        return sum(bin(int(octet)).count("1") for octet in netmask.split("."))

    def set_dns(self, primary_dns, secondary_dns=None):
        """
        Configure les serveurs DNS en modifiant le fichier /etc/resolv.conf.
        Attention : sur certaines distributions ce fichier peut être géré automatiquement par un service.
        """
        print("[INFO] Configuration du DNS...")
        resolv_content = f"nameserver {primary_dns}\n"
        if secondary_dns:
            resolv_content += f"nameserver {secondary_dns}\n"
        # On écrase le fichier /etc/resolv.conf avec la nouvelle configuration
        command = f"echo '{resolv_content}' | sudo tee /etc/resolv.conf"
        output, error = self.execute_command(command)
        if error.strip():
            print(f"[ERREUR] lors de la configuration du DNS : {error}")
        else:
            print(f"[INFO] DNS configuré avec {primary_dns}" + (f" et {secondary_dns}" if secondary_dns else "") + ".")

