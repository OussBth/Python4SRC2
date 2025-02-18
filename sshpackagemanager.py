import paramiko
import os
import tempfile
import logging
import re

logger = logging.getLogger(__name__)


def domain_to_dn(domain: str) -> str:
    """
    Convertit un domaine (ex: 'example.com') en DN (ex: 'dc=example,dc=com').
    """
    parts = domain.split('.')
    dn_parts = [f"dc={p}" for p in parts]
    return ",".join(dn_parts)


class SSHPackageManager:
    """
    Classe de base qui gère la connexion SSH et propose des méthodes
    générales pour installer, supprimer, mettre à jour, vérifier des paquets.
    """

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(hostname, username=username, password=password)
            logger.info(f"Connexion SSH établie avec {hostname}.")
        except Exception as e:
            logger.exception(f"Erreur lors de la connexion SSH à {hostname}: {e}")

    def execute_command(self, command):
        """
        Exécute une commande sur la machine distante en forçant un environnement non-interactif.
        """
        command = f"export TERM=xterm DEBIAN_FRONTEND=noninteractive && {command}"
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            return stdout.read().decode(), stderr.read().decode()
        except Exception as e:
            logger.exception(f"Exception lors de l'exécution de la commande: {command}")
            return "", str(e)

    def run_command(self, command, success_message=None, print_output=True):
        """
        Exécute une commande via execute_command, gère et affiche les erreurs.
        Retourne la sortie standard en cas de succès, sinon None.
        """
        try:
            output, error = self.execute_command(command)
            if error.strip():
                logger.error(f"Erreur lors de l'exécution de '{command}': {error.strip()}")
                return None
            else:
                if success_message:
                    logger.info(success_message)
                elif print_output:
                    logger.info(output.strip())
                return output.strip()
        except Exception as e:
            logger.exception(f"Exception lors de l'exécution de la commande: {command}")
            return None

    def install_single_package(self, package):
        logger.info(f"[INFO] Installation du paquet {package}...")
        self.run_command(f"sudo apt-get install -y {package}",
                         success_message=f"[INFO] Installation du paquet {package} terminée.")

    def install_packages(self, package_name):
        packages = package_name.split()
        self.run_command("sudo apt-get update",
                         success_message="[INFO] Mise à jour de la liste des paquets terminée.")
        for package in packages:
            self.install_single_package(package)

    def remove_package(self, package_name):
        logger.info(f"[INFO] Suppression du paquet {package_name}...")
        self.run_command(f"sudo apt-get remove -y {package_name}",
                         success_message=f"[INFO] Suppression du paquet {package_name} terminée.")
        self.run_command("sudo apt-get autoremove -y",
                         success_message="[INFO] Nettoyage des paquets inutilisés terminé.")

    def verify_package(self, package_name):
        logger.info(f"[INFO] Vérification de l'installation de {package_name} avec dpkg...")
        output = self.run_command(f"dpkg -l | grep {package_name}", print_output=False)
        if output and output.strip():
            logger.info(f"[OK] Le paquet {package_name} est installé.")
            return True
        else:
            logger.info(f"[INFO] Le paquet {package_name} n'est pas installé.")
            return False

    def update_package(self, package_name):
        if self.verify_package(package_name):
            logger.info(f"[INFO] Mise à jour du paquet {package_name}...")
            self.run_command(f"sudo apt-get update && sudo apt-get install --only-upgrade -y {package_name}",
                             success_message=f"[INFO] Mise à jour du paquet {package_name} terminée.")
        else:
            logger.info(f"[INFO] Le paquet {package_name} n'est pas installé, aucune mise à jour nécessaire.")

    def close_connection(self):
        self.client.close()
        logger.info("[INFO] Connexion SSH fermée.")


class WebManager(SSHPackageManager):
    """
    Gère les actions spécifiques au serveur web (Apache2).
    """

    def configure_apache2(self, site_name, port=80):
        logger.info("[INFO] Configuration du service Apache2...")
        self.run_command(f"sudo mkdir -p /var/www/html/{site_name}",
                         success_message=f"[INFO] Répertoire /var/www/html/{site_name} créé.")
        self.run_command(f"echo '<h1>Bienvenue sur le site {site_name}</h1>' | sudo tee /var/www/html/{site_name}/index.html",
                         success_message=f"[INFO] Page d'accueil pour {site_name} créée.")
        config_cmd = (
            "sudo bash -c 'cat > /etc/apache2/sites-available/"
            f"{site_name}.conf <<EOF\n"
            f"<VirtualHost *:{port}>\n"
            f"    ServerAdmin webmaster@localhost\n"
            f"    DocumentRoot /var/www/html/{site_name}\n"
            f"    ErrorLog ${{APACHE_LOG_DIR}}/error.log\n"
            f"    CustomLog ${{APACHE_LOG_DIR}}/access.log combined\n"
            f"</VirtualHost>\n"
            f"EOF'"
        )
        self.run_command(config_cmd,
                         success_message=f"[INFO] Fichier de configuration pour {site_name} créé.")
        self.run_command(f"sudo a2ensite {site_name}",
                         success_message=f"[INFO] Site {site_name} activé.")
        self.run_command("sudo systemctl reload apache2",
                         success_message="[INFO] Apache rechargé.")

    def list_apache_sites(self):
        logger.info("[INFO] Récupération des sites Apache disponibles...")
        output = self.run_command("ls /etc/apache2/sites-available | grep '.conf'", print_output=False)
        if output is not None:
            sites = [line.replace('.conf', '') for line in output.splitlines()]
            return sites
        return []

    def print_web_configuration(self, site_name):
        logger.info(f"[INFO] Affichage de la configuration pour le site : {site_name}")
        self.run_command(f"sudo /bin/cat /etc/apache2/sites-available/{site_name}.conf")

    def delete_apache_site(self, site_name):
        logger.info(f"[INFO] Suppression du site Apache : {site_name}...")
        self.run_command(f"sudo a2dissite {site_name}",
                         success_message=f"[INFO] Site {site_name} désactivé.")
        self.run_command(f"sudo rm -f /etc/apache2/sites-available/{site_name}.conf",
                         success_message="[INFO] Fichier de configuration supprimé.")
        self.run_command(f"sudo rm -rf /var/www/html/{site_name}",
                         success_message="[INFO] Répertoire du site supprimé.")
        self.run_command("sudo systemctl reload apache2",
                         success_message="[INFO] Apache rechargé.")


import ftplib

class FTPManager(SSHPackageManager):
    """
    Gère la configuration du serveur FTP (vsftpd)
    et ajoute des fonctions pour créer des dossiers et envoyer des fichiers via FTP.
    """

    def configure_vsftpd(self, anonymous_enable, local_enable, write_enable):
        logger.info("[INFO] Configuration de vsftpd...")
        self.run_command("sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak",
                         success_message="[INFO] Sauvegarde du fichier vsftpd.conf effectuée.")
        self.run_command(f"sudo sed -i 's/^#\\?anonymous_enable=.*/anonymous_enable={anonymous_enable.upper()}/' /etc/vsftpd.conf",
                         success_message="[INFO] Configuration de anonymous_enable mise à jour.")
        self.run_command(f"sudo sed -i 's/^#\\?local_enable=.*/local_enable={local_enable.upper()}/' /etc/vsftpd.conf",
                         success_message="[INFO] Configuration de local_enable mise à jour.")
        self.run_command(f"sudo sed -i 's/^#\\?write_enable=.*/write_enable={write_enable.upper()}/' /etc/vsftpd.conf",
                         success_message="[INFO] Configuration de write_enable mise à jour.")
        self.run_command("sudo systemctl restart vsftpd",
                         success_message="[INFO] vsftpd redémarré.")

    def print_ftp_configuration(self):
        logger.info("[INFO] Affichage de la configuration FTP...")
        self.run_command("sudo /usr/bin/grep -E '^(anonymous_enable|local_enable|write_enable)' /etc/vsftpd.conf")

    def create_ftp_directory(self, directory):
        """
        Crée un dossier (directory) sur le serveur FTP en utilisant ftplib.
        """
        logger.info(f"[INFO] Création du dossier {directory} via FTP.")
        try:
            with ftplib.FTP(self.hostname, self.username, self.password) as ftp:
                ftp.mkd(directory)
            logger.info(f"[INFO] Dossier '{directory}' créé avec succès.")
        except ftplib.all_errors as e:
            logger.error(f"[ERREUR] Impossible de créer le dossier '{directory}': {str(e)}")

    def store_ftp_file(self, local_path, remote_path):
        """
        Envoie (STOR) un fichier local vers le serveur FTP en utilisant ftplib.
        """
        logger.info(f"[INFO] Envoi du fichier '{local_path}' vers '{remote_path}'.")
        try:
            with ftplib.FTP(self.hostname, self.username, self.password) as ftp:
                with open(local_path, 'rb') as f:
                    ftp.storbinary(f"STOR {remote_path}", f)
            logger.info(f"[INFO] Fichier '{local_path}' envoyé avec succès vers '{remote_path}'.")
        except ftplib.all_errors as e:
            logger.error(f"[ERREUR] Échec de l'envoi du fichier : {str(e)}")


class LDAPManager(SSHPackageManager):
    """
    Gère l'installation, la configuration, la purge d'OpenLDAP,
    ainsi que l'ajout et la liste d'utilisateurs dans l'annuaire.
    """

    def install_and_configure_ldap_via_script(self, domain, org_name, admin_password):
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

echo "=== Fin du script d'installation OpenLDAP ==="
"""
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.sh') as tmpfile:
            tmpfile.write(script_content)
            local_script_path = tmpfile.name

        logger.info(f"[INFO] Script Bash créé localement : {local_script_path}")

        remote_script_path = "/tmp/config_openldap.sh"
        sftp = self.client.open_sftp()
        sftp.put(local_script_path, remote_script_path)
        sftp.close()

        self.run_command(f"sudo chmod +x {remote_script_path}",
                         success_message=f"[INFO] Permissions modifiées pour {remote_script_path}.")
        self.run_command(f"sudo dos2unix {remote_script_path}",
                         success_message=f"[INFO] Conversion du script {remote_script_path} effectuée.")
        self.run_command(f"ls -l {remote_script_path}")
        self.run_command("ls -l /tmp")
        self.run_command(f"sudo /bin/bash {remote_script_path}",
                         success_message="[INFO] Script d'installation OpenLDAP exécuté.")
        os.remove(local_script_path)

        base_dn = domain_to_dn(domain)
        create_ou_cmd = f"""echo "dn: ou=People,{base_dn}
objectClass: organizationalUnit
ou: People" | sudo ldapadd -x -D 'cn=admin,{base_dn}' -w {admin_password}"""
        self.run_command(create_ou_cmd,
                         success_message="[INFO] OU People créée avec succès.")

        logger.info("[INFO] Script d'installation LDAP exécuté avec succès (ou erreurs signalées ci-dessus).")

    def configure_ldap(self, domain, org_name, admin_password):
        logger.info("[INFO] Configuration d'OpenLDAP via dpkg-reconfigure (non-interactive).")
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
            self.run_command(cmd)
        self.run_command("sudo dpkg-reconfigure -f noninteractive slapd",
                         success_message="[INFO] Configuration d'OpenLDAP terminée.")

        base_dn = domain_to_dn(domain)
        create_ou_cmd = f"""echo "dn: ou=People,{base_dn}
objectClass: organizationalUnit
ou: People" | sudo ldapadd -x -D 'cn=admin,{base_dn}' -w {admin_password}"""
        self.run_command(create_ou_cmd,
                         success_message="[INFO] OU People créée avec succès après reconfiguration.")

    def add_ldap_user(self, user_cn, domain):
        base_dn = domain_to_dn(domain)
        logger.info(f"[INFO] Ajout de l'utilisateur {user_cn} dans {base_dn}...")

        ldif_content = f"""
dn: cn={user_cn},ou=People,{base_dn}
objectClass: inetOrgPerson
sn: {user_cn}
cn: {user_cn}
userPassword: secret
"""
        tmp_ldif_path = f"/tmp/{user_cn}.ldif"
        self.run_command(f"echo \"{ldif_content}\" > {tmp_ldif_path}",
                         success_message=f"[INFO] Fichier LDIF pour {user_cn} créé.")
        self.run_command(f"sudo ldapadd -x -D 'cn=admin,{base_dn}' -w admin -f {tmp_ldif_path}",
                         success_message=f"[INFO] Utilisateur LDAP {user_cn} ajouté.")

    def delete_ldap_user(self, user_cn, domain, admin_password):
        base_dn = domain_to_dn(domain)
        dn = f"cn={user_cn},ou=People,{base_dn}"
        delete_cmd = f"sudo ldapdelete -x -D 'cn=admin,{base_dn}' -w {admin_password} '{dn}'"
        self.run_command(delete_cmd,
                         success_message=f"[INFO] Utilisateur {user_cn} supprimé avec succès.")

    def add_ou(self, ou_name, domain, admin_password):
        base_dn = domain_to_dn(domain)
        add_ou_cmd = f"""echo "dn: ou={ou_name},{base_dn}
objectClass: organizationalUnit
ou: {ou_name}" | sudo ldapadd -x -D 'cn=admin,{base_dn}' -w {admin_password}"""
        self.run_command(add_ou_cmd,
                         success_message=f"[INFO] OU {ou_name} créée avec succès.")

    def remove_ou(self, ou_name, domain, admin_password):
        base_dn = domain_to_dn(domain)
        delete_ou_cmd = f"sudo ldapdelete -x -D 'cn=admin,{base_dn}' -w {admin_password} 'ou={ou_name},{base_dn}'"
        self.run_command(delete_ou_cmd,
                         success_message=f"[INFO] OU {ou_name} supprimée avec succès.")

    def list_ous(self, domain="example.com"):
        base_dn = domain_to_dn(domain)
        logger.info(f"[INFO] Listing des OU sous {base_dn}...")
        self.run_command(f"ldapsearch -x -LLL -b '{base_dn}' '(&(objectClass=organizationalUnit)(ou=*))' ou")

    def list_ldap_users(self, domain="example.com"):
        base_dn = domain_to_dn(domain)
        logger.info(f"[INFO] Listing des utilisateurs sous 'ou=People,{base_dn}'...")
        self.run_command(f"ldapsearch -x -LLL -b 'ou=People,{base_dn}' cn")

    def remove_ldap_config(self):
        logger.info("[INFO] Suppression/Purge de la configuration OpenLDAP...")
        self.run_command("sudo apt-get remove --purge -y slapd",
                         success_message="[INFO] Package slapd purgé.")
        self.run_command("sudo rm -rf /etc/ldap/slapd.d /var/lib/ldap",
                         success_message="[INFO] Dossiers de configuration supprimés.")
        self.run_command("sudo apt-get autoremove -y",
                         success_message="[INFO] Nettoyage des paquets inutilisés terminé.")
        logger.info("[INFO] Configuration OpenLDAP supprimée (purge) avec succès.")

class LinuxUserManager(SSHPackageManager):
    """
    Gère la création, suppression, modification de mot de passe et la gestion des groupes utilisateurs.
    """

    def create_user(self, username, password):
        logger.info(f"[INFO] Création de l'utilisateur {username}.")
        output = self.run_command(f"id -u {username}", print_output=False)
        if output and "no such user" not in output:
            logger.warning(f"[WARNING] L'utilisateur {username} existe déjà.")
            return
        self.run_command(f"sudo useradd -m {username}",
                         success_message=f"[INFO] Utilisateur {username} créé.")
        self.run_command(f"echo '{username}:{password}' | sudo chpasswd",
                         success_message="[INFO] Mot de passe défini avec succès.")

    def delete_user(self, username):
        logger.info(f"[INFO] Suppression de l'utilisateur {username}.")
        output = self.run_command(f"id -u {username}", print_output=False)
        if output is None:
            logger.warning(f"[WARNING] L'utilisateur {username} n'existe pas.")
            return
        self.run_command(f"sudo userdel -r {username}",
                         success_message=f"[INFO] Utilisateur {username} supprimé.")

    def change_password(self, username, new_password):
        logger.info(f"[INFO] Changement du mot de passe de {username}.")
        output = self.run_command(f"id -u {username}", print_output=False)
        if output is None:
            logger.warning(f"[WARNING] L'utilisateur {username} n'existe pas.")
            return
        self.run_command(f"echo '{username}:{new_password}' | sudo chpasswd",
                         success_message="[INFO] Mot de passe modifié avec succès.")

    def add_group_user(self, username, group_name):
        logger.info(f"[INFO] Ajout du groupe {group_name} pour l'utilisateur {username}.")
        self.run_command(f"sudo groupadd {group_name}",
                         success_message=f"[INFO] Groupe {group_name} ajouté.")

    def del_group_user(self, username, group_name):
        logger.info(f"[INFO] Suppression du groupe {group_name} pour l'utilisateur {username}.")
        self.run_command(f"sudo deluser {username} {group_name}",
                         success_message=f"[INFO] Groupe {group_name} supprimé pour {username}.")
    

    def list_groups(self, username):
        if username:
            logger.info(f"[INFO] Groupes de {username} :")
            self.run_command(f"id -nG {username}")
        else:
            logger.info("[INFO] Liste de tous les groupes :")
            self.run_command("cut -d: -f1 /etc/group")

    def list_users(self):
        logger.info("[INFO] Liste des utilisateurs :")
        self.run_command("cut -d: -f1 /etc/passwd")



class NetworkManager(SSHPackageManager):
    """
    Gère les configurations réseau et la configuration du DNS.
    """

    # def list_interfaces(self):
    #     logger.info("[INFO] Récupération des interfaces réseau...")
    #     self.run_command("ip link show")
    def list_interfaces_details(self):
        """
        Affiche pour chaque interface son nom et son adresse IP (si elle existe).
        """
        output = self.run_command("ip addr show", print_output=False)
        interfaces = {}
        current_interface = None

        # Parcours ligne par ligne de la sortie de "ip addr show"
        for line in output.splitlines():
            # Si la ligne commence par un chiffre suivi d'un ':' on détecte le nom de l'interface
            header_match = re.match(r'^\d+: (\S+):', line)
            if header_match:
                current_interface = header_match.group(1)
                interfaces[current_interface] = None
            else:
                # Recherche d'une adresse IP sur la ligne (après "inet ")
                if current_interface:
                    inet_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                    if inet_match:
                        interfaces[current_interface] = inet_match.group(1)
        
        # Affichage du résultat
        for iface, ip in interfaces.items():
            if ip:
                print(f"{iface}: {ip}")
            else:
                print(f"{iface}: Aucun IP assignée")

    def get_interface_status(self, interface):
        logger.info(f"[INFO] Récupération de l'état de l'interface {interface}...")
        self.run_command(f"ip addr show {interface}")


    def enable_interface(self, interface):
        logger.info(f"[INFO] Activation de l'interface {interface}...")
        self.run_command(f"sudo ip link set {interface} up",
                         success_message=f"[INFO] Interface {interface} activée.")
        
    def disable_interface(self, interface):
        logger.info(f"[INFO] Désactivation de l'interface {interface}...")
        self.run_command(f"sudo ip link set {interface} down",
                         success_message=f"[INFO] Interface {interface} désactivée.")

    def configure_static_ip(self, interface, ip, netmask, gateway):
        logger.info(f"[INFO] Configuration de l'IP statique sur {interface}...")
        self.run_command(f"sudo ip addr flush dev {interface}",
                         success_message=f"[INFO] Configuration IP de {interface} réinitialisée.")
        prefix = self.netmask_to_prefix(netmask)
        self.run_command(f"sudo ip addr add {ip}/{prefix} dev {interface}",
                         success_message=f"[INFO] {interface} configurée avec l'IP {ip}/{prefix}.")
        self.run_command(f"sudo ip route add default via {gateway} dev {interface}",
                         success_message=f"[INFO] Route par défaut configurée via {gateway}.")
        self.list_interfaces_details()
        self.run_command("ip route show")

    def configure_dhcp(self, interface):
        logger.info(f"[INFO] Configuration DHCP pour l'interface {interface}...")
        self.run_command(f"sudo dhclient {interface}",
                         success_message=f"[INFO] Configuration DHCP pour {interface} terminée.")
        self.list_interfaces_details()
    
    def list_dhcp_leases(self):
        logger.info("[INFO] Liste des baux DHCP actifs...")
        self.run_command("cat /var/lib/dhcp/dhclient.leases")
        logger.info("[INFO] Liste des baux DHCP actifs :")
        self.run_command("ip addr show")

    def reset_dns(self):
        logger.info("[INFO] Réinitialisation du DNS...")
        self.run_command("sudo rm /etc/resolv.conf",
                         success_message="[INFO] Fichier /etc/resolv.conf réinitialisé.")
        self.run_command("sudo echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf",
                         success_message="[INFO] DNS réinitialisé avec Google Public DNS.")
        self.run_command("cat /etc/resolv.conf")
        logger.info("[INFO] DNS réinitialisé avec Google Public DNS.")
    
    def get_dns(self):
        logger.info("[INFO] Récupération des serveurs DNS actuels...")
        self.run_command("cat /etc/resolv.conf")
        logger.info("[INFO] Serveurs DNS actuels :")

    def netmask_to_prefix(self, netmask):
        return sum(bin(int(octet)).count("1") for octet in netmask.split("."))

    def set_dns(self, primary_dns, secondary_dns=None):
        logger.info("[INFO] Configuration du DNS...")
        resolv_content = f"nameserver {primary_dns}\n"
        if secondary_dns:
            resolv_content += f"nameserver {secondary_dns}\n"
        command = f"echo '{resolv_content}' | sudo tee /etc/resolv.conf"
        self.run_command(command,
                         success_message=f"[INFO] DNS configuré avec {primary_dns}" + (f" et {secondary_dns}" if secondary_dns else "") + ".")
        self.run_command("cat /etc/resolv.conf")
