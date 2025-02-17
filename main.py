import paramiko
import os
from getpass import getpass
import logging
import sys
from colored_formatter import ColoredFormatter

# Configuration du logging pour les logs techniques (avec date/heure)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)

# Fonction utilitaire pour afficher les menus avec couleurs, sans date/heure
def menu_print(message, level="INFO"):
    color = ColoredFormatter.COLORS.get(level, ColoredFormatter.RESET)
    print(f"{color}{message}{ColoredFormatter.RESET}")

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

from sshpackagemanager import (
    SSHPackageManager,
    WebManager,
    FTPManager,
    LDAPManager,
    LinuxUserManager,
    NetworkManager
)

# Vos fonctions de sous-menus (inchangées) :
def package_menu(package_manager, is_admin):
    while True:
        clear_screen()
        menu_print("[ MENU Paquets Classiques ]", level="INFO")
        if is_admin:
            menu_print("1. Installer des paquets", level="INFO")
            menu_print("2. Désinstaller un paquet", level="INFO")
            menu_print("3. Mettre à jour un paquet", level="INFO")
        menu_print("4. Vérifier l'installation d'un paquet", level="INFO")
        menu_print("5. Retour au menu principal", level="INFO")

        choice = input("Sélectionnez une option : ")
        if choice == "1" and is_admin:
            packages = input("Entrez les paquets à installer (séparés par des espaces) : ")
            package_manager.install_packages(packages)
        elif choice == "2" and is_admin:
            package = input("Entrez le nom du paquet à désinstaller : ")
            package_manager.remove_package(package)
        elif choice == "3" and is_admin:
            package = input("Entrez le nom du paquet à mettre à jour : ")
            package_manager.update_package(package)
        elif choice == "4":
            package = input("Entrez le nom du paquet à vérifier : ")
            package_manager.verify_package(package)
        elif choice == "5":
            break
        else:
            logger.error("[ERREUR] Choix invalide ou accès refusé.")
        input("Appuyez sur Entrée pour continuer...")

def web_menu(web_manager, is_admin):
    while True:
        clear_screen()
        menu_print("[ MENU Web ]", level="INFO")
        if is_admin:
            menu_print("1. Installer Apache2 + PHP", level="INFO")
            menu_print("2. Configurer Apache2 (Nouveau site)", level="INFO")
            menu_print("3. Supprimer un site", level="INFO")
        menu_print("4. Afficher la configuration Web", level="INFO")
        menu_print("5. Retour au menu principal", level="INFO")

        choice = input("Sélectionnez une option : ")
        if choice == "1" and is_admin:
            web_manager.install_packages("apache2 php8.2 libapache2-mod-php8.2")
        elif choice == "2" and is_admin:
            site_name = input("Nom du site : ")
            port_str = input("Port (par défaut 80) : ")
            if not port_str.strip():
                port = 80
            else:
                try:
                    port = int(port_str)
                except ValueError:
                    logger.error("[ERREUR] Port invalide, utilisation du port 80 par défaut.")
                    port = 80
            web_manager.configure_apache2(site_name, port)
        elif choice == "4":
            menu_print("\nSites disponibles :", level="INFO")
            sites = web_manager.list_apache_sites()
            if sites:
                for idx, site in enumerate(sites, 1):
                    menu_print(f"{idx}. {site}", level="INFO")
                try:
                    site_index = int(input("Sélectionnez le site à afficher (numéro) : ")) - 1
                    if 0 <= site_index < len(sites):
                        web_manager.print_web_configuration(sites[site_index])
                    else:
                        logger.error("[ERREUR] Choix invalide.")
                except ValueError:
                    logger.error("[ERREUR] Entrée non numérique.")
            else:
                menu_print("[INFO] Aucun site Apache trouvé.", level="INFO")
        elif choice == "3" and is_admin:
            menu_print("\nSites disponibles :", level="INFO")
            sites = web_manager.list_apache_sites()
            if sites:
                for idx, site in enumerate(sites, 1):
                    menu_print(f"{idx}. {site}", level="INFO")
                try:
                    site_index = int(input("Sélectionnez le site à supprimer (numéro) : ")) - 1
                    if 0 <= site_index < len(sites):
                        confirmation = input(f"Êtes-vous sûr de vouloir supprimer le site '{sites[site_index]}' ? (yes/no) : ").lower()
                        if confirmation == "yes":
                            web_manager.delete_apache_site(sites[site_index])
                            menu_print(f"[INFO] Site '{sites[site_index]}' supprimé avec succès.", level="INFO")
                        else:
                            menu_print("[INFO] Suppression annulée.", level="INFO")
                    else:
                        logger.error("[ERREUR] Choix invalide.")
                except ValueError:
                    logger.error("[ERREUR] Entrée non numérique.")
            else:
                menu_print("[INFO] Aucun site Apache trouvé.", level="INFO")
        elif choice == "5":
            break
        else:
            logger.error("[ERREUR] Choix invalide ou accès refusé.")
        input("Appuyez sur Entrée pour continuer...")

def ftp_menu(ftp_manager, is_admin):
    while True:
        clear_screen()
        menu_print("[ MENU FTP ]", level="INFO")
        if is_admin:
            menu_print("1. Installer le serveur FTP (vsftpd)", level="INFO")
            menu_print("2. Configurer le serveur FTP", level="INFO")
        menu_print("3. Afficher la configuration FTP", level="INFO")
        menu_print("4. Retour au menu principal", level="INFO")

        choice = input("Sélectionnez une option : ")
        if choice == "1" and is_admin:
            ftp_manager.install_single_package("vsftpd")
        elif choice == "2" and is_admin:
            menu_print("\nConfiguration du serveur FTP (vsftpd) :", level="INFO")
            anonymous_enable = input("Autoriser les connexions anonymes ? (yes/no) : ").strip().lower()
            local_enable = input("Autoriser les utilisateurs locaux ? (yes/no) : ").strip().lower()
            write_enable = input("Autoriser les écritures (upload) ? (yes/no) : ").strip().lower()
            ftp_manager.configure_vsftpd(anonymous_enable, local_enable, write_enable)
        elif choice == "3":
            ftp_manager.print_ftp_configuration()
        elif choice == "4":
            break
        else:
            logger.error("[ERREUR] Choix invalide ou accès refusé.")
        input("Appuyez sur Entrée pour continuer...")

def ldap_menu(ldap_manager, is_admin):
    while True:
        clear_screen()
        menu_print("[ MENU LDAP ]", level="INFO")
        if is_admin:
            menu_print("1. Installer & configurer OpenLDAP (non-interactif)", level="INFO")
            menu_print("2. Reconfigurer OpenLDAP (changer domaine, org, mot de passe)", level="INFO")
            menu_print("3. Ajouter un utilisateur LDAP", level="INFO")
            menu_print("4. Lister les utilisateurs LDAP", level="INFO")
            menu_print("5. Supprimer la configuration OpenLDAP", level="INFO")
            menu_print("6. Supprimer un utilisateur LDAP", level="INFO")
            menu_print("7. Ajouter une OU", level="INFO")
            menu_print("8. Supprimer une OU", level="INFO")
            menu_print("9. Lister les OU", level="INFO")
        menu_print("0. Retour au menu principal", level="INFO")

        choice = input("Sélectionnez une option : ")
        if choice == "1" and is_admin:
            domain = input("Entrez le nom de domaine LDAP (ex: example.com) : ").strip() or "example.com"
            org = input("Entrez le nom de l'organisation (ex: ExampleOrg) : ").strip() or "ExampleOrg"
            admin_pass = getpass("Entrez le mot de passe admin LDAP : ").strip() or "admin"
            ldap_manager.install_and_configure_ldap_via_script(domain, org, admin_pass)
        elif choice == "2" and is_admin:
            domain = input("Entrez le nouveau domaine LDAP (ex: example.com) : ").strip() or "example.com"
            org = input("Entrez le nouveau nom de l'organisation (ex: ExampleOrg) : ").strip() or "ExampleOrg"
            admin_pass = getpass("Entrez le nouveau mot de passe admin LDAP : ").strip() or "admin"
            ldap_manager.configure_ldap(domain, org, admin_pass)
        elif choice == "3" and is_admin:
            user_cn = input("Nom (cn) de l'utilisateur à ajouter : ").strip()
            domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
            ldap_manager.add_ldap_user(user_cn, domain)
        elif choice == "4" and is_admin:
            domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
            ldap_manager.list_ldap_users(domain)
        elif choice == "5" and is_admin:
            confirmation = input("Êtes-vous sûr de vouloir PURGER OpenLDAP ? (yes/no) : ").lower()
            if confirmation == "yes":
                ldap_manager.remove_ldap_config()
            else:
                menu_print("[INFO] Suppression annulée.", level="INFO")
        elif choice == "6" and is_admin:
            user_cn = input("Nom (cn) de l'utilisateur à supprimer : ").strip()
            domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
            admin_pass = getpass("Entrez le mot de passe admin LDAP : ").strip() or "admin"
            ldap_manager.delete_ldap_user(user_cn, domain, admin_pass)
        elif choice == "7" and is_admin:
            ou_name = input("Nom de l'OU à ajouter : ").strip()
            domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
            admin_pass = getpass("Entrez le mot de passe admin LDAP : ").strip() or "admin"
            ldap_manager.add_ou(ou_name, domain, admin_pass)
        elif choice == "8" and is_admin:
            ou_name = input("Nom de l'OU à supprimer : ").strip()
            domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
            admin_pass = getpass("Entrez le mot de passe admin LDAP : ").strip() or "admin"
            ldap_manager.remove_ou(ou_name, domain, admin_pass)
        elif choice == "9" and is_admin:
            domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
            ldap_manager.list_ous(domain)
        elif choice == "0":
            break
        else:
            logger.error("[ERREUR] Choix invalide ou accès refusé.")
        input("Appuyez sur Entrée pour continuer...")

def linux_user_menu(user_manager, is_admin):
    while True:
        clear_screen()
        menu_print("[ MENU Utilisateurs Linux ]", level="INFO")
        if is_admin:
            menu_print("1. Créer un utilisateur", level="INFO")
            menu_print("2. Supprimer un utilisateur", level="INFO")
            menu_print("3. Changer un mot de passe", level="INFO")
        menu_print("4. Lister les groupes (d'un utilisateur)", level="INFO")
        menu_print("5. Lister les utilisateurs", level="INFO")
        menu_print("6. Retour au menu principal", level="INFO")

        choice = input("Sélectionnez une option : ")
        if choice == "1" and is_admin:
            username = input("Nom de l'utilisateur : ")
            password = getpass("Mot de passe : ")
            user_manager.create_user(username, password)
        elif choice == "2" and is_admin:
            username = input("Nom de l'utilisateur : ")
            confirmation = input(f"Êtes-vous sûr de vouloir supprimer l'utilisateur {username} ? (yes/no) : ").lower()
            if confirmation == "yes":
                user_manager.delete_user(username)
            else:
                menu_print("[INFO] Suppression annulée.", level="INFO")
        elif choice == "3" and is_admin:
            username = input("Nom de l'utilisateur : ")
            new_password = getpass("Nouveau mot de passe : ")
            user_manager.change_password(username, new_password)
        elif choice == "4":
            username = input("Nom de l'utilisateur (laisser vide pour lister tous les groupes) : ")
            user_manager.list_groups(username)
        elif choice == "5":
            user_manager.list_users()
        elif choice == "6":
            break
        else:
            logger.error("[ERREUR] Choix invalide ou accès refusé.")
        input("Appuyez sur Entrée pour continuer...")

def network_menu(network_manager, is_admin):
    while True:
        clear_screen()
        menu_print("[ MENU Réseau et DNS ]", level="INFO")
        menu_print("1. Lister les interfaces réseau", level="INFO")
        if is_admin:
            menu_print("2. Activer une interface", level="INFO")
            menu_print("3. Désactiver une interface", level="INFO")
            menu_print("4. Configurer une IP statique", level="INFO")
            menu_print("5. Configurer une IP dynamique (DHCP)", level="INFO")
            menu_print("6. Lister les baux DHCP", level="INFO")
            menu_print("7. Configurer les serveurs DNS", level="INFO")
            menu_print("8. Reset les DNS", level="INFO")
            menu_print("9. Lister les DNS actuels", level="INFO")
            menu_print("10. Retour au menu principal", level="INFO")
        choice = input("Sélectionnez une option : ")
        if choice == "1":
            network_manager.list_interfaces_details()
        elif choice == "2" and is_admin:
            menu_print("[INFO] Interfaces disponibles :", level="INFO")
            network_manager.list_interfaces_details()
            interface = input("Entrez le nom de l'interface à activer : ")
            network_manager.enable_interface(interface)
        elif choice == "3" and is_admin:
            menu_print("[INFO] Interfaces disponibles :", level="INFO")
            network_manager.list_interfaces_details()
            interface = input("Entrez le nom de l'interface à désactiver : ")
            network_manager.disable_interface(interface)
        elif choice == "4" and is_admin:
            menu_print("[INFO] Interfaces disponibles :", level="INFO")
            network_manager.list_interfaces_details()
            interface = input("Entrez le nom de l'interface à configurer : ")
            ip = input("Entrez l'adresse IP : ")
            netmask = input("Entrez le masque de sous-réseau (ex: 255.255.255.0) : ")
            gateway = input("Entrez la passerelle par défaut : ")
            network_manager.configure_static_ip(interface, ip, netmask, gateway)
        elif choice == "5" and is_admin:
            menu_print("[INFO] Interfaces disponibles :", level="INFO")
            network_manager.list_interfaces_details()
            interface = input("Entrez le nom de l'interface à configurer en DHCP : ")
            network_manager.configure_dhcp(interface)
            network_manager.list_dhcp_leases()
        elif choice == "6" and is_admin:
            network_manager.list_dhcp_leases()
        elif choice == "7" and is_admin:
            primary_dns = input("Entrez l'adresse du DNS primaire : ")
            secondary_dns = input("Entrez l'adresse du DNS secondaire (laisser vide si aucun) : ")
            secondary_dns = secondary_dns if secondary_dns.strip() != "" else None
            network_manager.set_dns(primary_dns, secondary_dns)
        elif choice == "8" and is_admin:
            network_manager.reset_dns()
        elif choice == "9" and is_admin:
            network_manager.list_dns()
        elif (choice == "10" and is_admin) or (choice == "10" and not is_admin):
            break
        else:
            logger.error("[ERREUR] Choix invalide ou accès refusé.")
        input("Appuyez sur Entrée pour continuer...")

def main_menu(package_manager, web_manager, ftp_manager, ldap_manager, linux_user_manager, network_manager, is_admin):
    while True:
        clear_screen()
        menu_print("[ MENU PRINCIPAL ]", level="INFO")
        menu_print("1. Gestion des paquets classiques", level="INFO")
        menu_print("2. Gestion des paquets web (Apache)", level="INFO")
        menu_print("3. Gestion du serveur FTP", level="INFO")
        menu_print("4. Gestion du serveur LDAP", level="INFO")
        menu_print("5. Gestion des utilisateurs Linux", level="INFO")
        menu_print("6. Gestion du réseau et DNS", level="INFO")
        menu_print("7. Quitter", level="INFO")

        choice = input("Sélectionnez une option : ")
        if choice == "1":
            package_menu(package_manager, is_admin)
        elif choice == "2":
            web_menu(web_manager, is_admin)
        elif choice == "3":
            ftp_menu(ftp_manager, is_admin)
        elif choice == "4":
            ldap_menu(ldap_manager, is_admin)
        elif choice == "5":
            linux_user_menu(linux_user_manager, is_admin)
        elif choice == "6":
            network_menu(network_manager, is_admin)
        elif choice == "7":
            logger.info("[INFO] Fermeture du programme.")
            break
        else:
            logger.error("[ERREUR] Choix invalide.")
        input("Appuyez sur Entrée pour continuer...")

def authenticate_remote(hostname):
    logger.info("[AUTH] Authentification requise...")
    user = input("Nom d'utilisateur SSH : ")
    password = getpass("Mot de passe SSH : ")

    temp_client = paramiko.SSHClient()
    temp_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        temp_client.connect(hostname, username=user, password=password)
    except Exception as e:
        logger.error(f"[ERREUR] Échec de la connexion SSH : {str(e)}")
        return None, None, False

    try:
        stdin, stdout, stderr = temp_client.exec_command(f"id -nG {user}")
        groups = stdout.read().decode().strip().split()
    except Exception as e:
        logger.error(f"[ERREUR] Échec de l'exécution de la commande d'identification : {str(e)}")
        groups = []
    finally:
        temp_client.close()

    is_admin = ('sudo' in groups) or ('admin' in groups)
    return user, password, is_admin

if __name__ == "__main__":
    clear_screen()
    hostname = input("Entrez le nom d'hôte ou l'adresse IP de la machine distante : ")

    ssh_user, ssh_pass, is_admin = authenticate_remote(hostname)
    if not ssh_user or not ssh_pass:
        logger.error("[ERREUR] Impossible de continuer sans authentification correcte.")
        exit(1)

    package_manager = SSHPackageManager(hostname, ssh_user, ssh_pass)
    web_manager = WebManager(hostname, ssh_user, ssh_pass)
    ftp_manager = FTPManager(hostname, ssh_user, ssh_pass)
    ldap_manager = LDAPManager(hostname, ssh_user, ssh_pass)
    linux_user_manager = LinuxUserManager(hostname, ssh_user, ssh_pass)
    network_manager = NetworkManager(hostname, ssh_user, ssh_pass)

    main_menu(package_manager, web_manager, ftp_manager, ldap_manager, linux_user_manager, network_manager, is_admin)

    package_manager.close_connection()
    web_manager.close_connection()
    ftp_manager.close_connection()
    ldap_manager.close_connection()
    linux_user_manager.close_connection()
    network_manager.close_connection()
    logger.info("[INFO] Connexions SSH fermées.")
