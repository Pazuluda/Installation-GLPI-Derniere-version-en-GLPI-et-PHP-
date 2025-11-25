#!/bin/bash

# =====================================================
# Script installation GLPI 11.0.2 sur Debian 13
# Nginx + PHP FPM + HTTPS signe par CA interne MyCA
# =====================================================

clear
echo "====================================================="
echo "  Script installation GLPI 11.0.2 - Debian 13"
echo "====================================================="
echo
echo " - Nginx + PHP FPM"
echo " - MariaDB"
echo " - GLPI 11.0.2 dans /var/www/html/glpi"
echo " - HTTPS avec certificat signe par CA interne MyCA"
echo " - Possibilite d utiliser votre propre CA myCA"
echo " - Redirection HTTP (80) vers HTTPS (443)"
echo

read -p " Avez vous execute ce script en tant que root ? (O/N) : " confirm
case "$confirm" in
    N|n)
        echo " Veuillez re executer ce script en tant que root."
        exit 0
        ;;
esac

echo
read -p " Nom ou IP utilise pour acceder a GLPI (ex: www.liam.glpi ou 192.168.1.10) : " GLPI_HOST
if [ -z "$GLPI_HOST" ]; then
    echo " Vous devez saisir un nom ou une IP."
    exit 1
fi

# ---------- 1) Mise a jour du systeme ----------
clear
echo "[1/16] Mise a jour du systeme"
apt update
apt upgrade -y
apt install -y wget openssl

# ---------- 2) Installation MariaDB ----------
clear
echo "[2/16] Installation du serveur SQL MariaDB"
apt install -y mariadb-server

# ---------- 3) Initialisation MariaDB ----------
clear
echo "[3/16] Initialisation de MariaDB (mariadb-secure-installation)"
echo " Repondez en general avec les choix par defaut."
sleep 3
mariadb-secure-installation

# ---------- 4) Creation base glpidb + user adminglpi ----------
clear
echo "[4/16] Creation de la base glpidb et de l utilisateur adminglpi"
mysqladmin -uroot create glpidb
mysql -uroot -e "GRANT ALL ON glpidb.* TO adminglpi@localhost IDENTIFIED BY 'Ertyuiop,64'"

# ---------- 5) Suppression Apache2 + installation Nginx ----------
clear
echo "[5/16] Suppression d Apache2 (si present) et installation de Nginx"

echo " - Arret et desactivation d Apache2"
systemctl stop apache2 2>/dev/null || true
systemctl disable apache2 2>/dev/null || true
systemctl mask apache2 2>/dev/null || true

echo " - Purge des paquets Apache2"
apt purge -y apache2 apache2-bin apache2-data apache2-utils apache2-doc apache2-suexec-pristine apache2-suexec-custom libapache2-mod-php* libapache2-mod-fcgid 2>/dev/null || true
apt autoremove -y --purge 2>/dev/null || true
rm -rf /etc/apache2 2>/dev/null || true

echo " - Installation de Nginx"
apt install -y nginx
systemctl enable nginx
systemctl start nginx

# ---------- 6) Installation PHP + durcissement ----------
clear
echo "[6/16] Installation de PHP et des dependances"
apt install -y php-cli php-fpm php-mysql php-mbstring php-curl php-gd php-xml php-intl php-ldap php-apcu php-zip php-bz2 php-bcmath

PHP_FPM_VER="8.4"

echo " - Durcissement configuration PHP (session.cookie_httponly et session.cookie_secure)"
for SAPI in fpm cli; do
    PHP_INI="/etc/php/${PHP_FPM_VER}/${SAPI}/php.ini"
    if [ -f "$PHP_INI" ]; then
        echo "   -> Mise a jour de $PHP_INI"
        sed -i 's/^;*session.cookie_httponly *= *.*/session.cookie_httponly = 1/' "$PHP_INI"
        sed -i 's/^;*session.cookie_secure *= *.*/session.cookie_secure = On/' "$PHP_INI"
    else
        echo "   [AVERTISSEMENT] Fichier $PHP_INI introuvable"
    fi
done

systemctl restart php${PHP_FPM_VER}-fpm

# ---------- 7) Nettoyage du document root ----------
clear
echo "[7/16] Preparation de /var/www/html"
rm -f /var/www/html/index.nginx-debian.html

# ---------- 8) Telechargement GLPI 11.0.2 ----------
clear
echo "[8/16] Telechargement de GLPI 11.0.2 et installation dans /var/www/html/glpi"
cd /tmp
wget -O glpi-11.0.2.tgz https://github.com/glpi-project/glpi/releases/download/11.0.2/glpi-11.0.2.tgz
tar -xvzf glpi-11.0.2.tgz

rm -rf /var/www/html/glpi
mkdir -p /var/www/html/glpi
cp -r glpi/* /var/www/html/glpi/

# ---------- 9) Droits sur GLPI ----------
clear
echo "[9/16] Application des droits sur /var/www/html/glpi"
chown -R www-data:www-data /var/www/html/glpi
chmod -R 755 /var/www/html/glpi

# ---------- 10) Securisation GLPI (dossiers hors du root) ----------
clear
echo "[10/16] Securisation GLPI (dossiers config et fichiers)"

echo " - Creation du fichier inc/downstream.php"
cat > /var/www/html/glpi/inc/downstream.php << 'EOF'
<?php
define('GLPI_CONFIG_DIR', '/etc/glpi/');
if (file_exists(GLPI_CONFIG_DIR . '/local_define.php')) {
   require_once GLPI_CONFIG_DIR . '/local_define.php';
}
?>
EOF

echo " - Creation du dossier /etc/glpi et du fichier local_define.php"
mkdir -p /etc/glpi
cat > /etc/glpi/local_define.php << 'EOF'
<?php
define('GLPI_VAR_DIR', '/var/lib/glpi');
define('GLPI_LOG_DIR', '/var/log/glpi');
?>
EOF

chown -R www-data:www-data /etc/glpi

echo " - Deplacement des donnees GLPI dans /var/lib/glpi"
mkdir -p /var/lib/glpi
cp -r /var/www/html/glpi/files/* /var/lib/glpi/ 2>/dev/null || true
chown -R www-data:www-data /var/lib/glpi

echo " - Creation du dossier de logs /var/log/glpi"
mkdir -p /var/log/glpi
chown -R www-data:www-data /var/log/glpi

echo " - Suppression des dossiers sensibles du code source"
rm -rf /var/www/html/glpi/files
rm -rf /var/www/html/glpi/config

echo " - Durcissement des droits dans /var/www/html/glpi"
find /var/www/html/glpi -type f -exec chmod 644 {} \;
find /var/www/html/glpi -type d -exec chmod 755 {} \;

# ---------- 11) CA interne MyCA + certificat SSL ----------
clear
echo "[11/16] CA interne MyCA + certificat SSL pour ${GLPI_HOST}"

mkdir -p /etc/ssl/glpi

# 11.1 - Creation ou reutilisation de la CA interne MyCA
if [[ -f /etc/ssl/glpi/MyCA.crt && -f /etc/ssl/glpi/MyCA.key ]]; then
    echo " - CA MyCA deja presente, reutilisation."
else
    echo " - Creation d une CA interne MyCA"
    openssl genrsa -out /etc/ssl/glpi/MyCA.key 4096
    openssl req -x509 -new -nodes \
        -key /etc/ssl/glpi/MyCA.key \
        -sha256 -days 3650 \
        -out /etc/ssl/glpi/MyCA.crt \
        -subj "/CN=MyGLPI-CA"
fi

chmod 600 /etc/ssl/glpi/MyCA.key
chmod 644 /etc/ssl/glpi/MyCA.crt

# 11.2 - Fichier de configuration OpenSSL pour le certificat GLPI (SAN)
GLPI_SSL_CONF="/etc/ssl/glpi/openssl-glpi.cnf"

if [[ "$GLPI_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    cat > "$GLPI_SSL_CONF" <<EOF
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
CN = ${GLPI_HOST}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = ${GLPI_HOST}
EOF
else
    cat > "$GLPI_SSL_CONF" <<EOF
[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
CN = ${GLPI_HOST}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${GLPI_HOST}
EOF
fi

# 11.3 - Generation de la cle privee et de la CSR GLPI
echo " - Generation de la cle privee GLPI et de la CSR"
openssl genrsa -out /etc/ssl/glpi/glpi.key 4096
openssl req -new \
  -key /etc/ssl/glpi/glpi.key \
  -out /etc/ssl/glpi/glpi.csr \
  -config "$GLPI_SSL_CONF"

# 11.4 - Signature du certificat GLPI avec la CA MyCA
echo " - Signature du certificat GLPI avec MyCA"
openssl x509 -req \
  -in /etc/ssl/glpi/glpi.csr \
  -CA /etc/ssl/glpi/MyCA.crt \
  -CAkey /etc/ssl/glpi/MyCA.key \
  -CAcreateserial \
  -out /etc/ssl/glpi/glpi.crt \
  -days 825 -sha256 \
  -extfile "$GLPI_SSL_CONF" -extensions v3_req

chmod 600 /etc/ssl/glpi/glpi.key
chmod 644 /etc/ssl/glpi/glpi.crt

echo
echo " Certificats generes :"
echo "   - CA interne : /etc/ssl/glpi/MyCA.crt"
echo "   - Certificat site GLPI : /etc/ssl/glpi/glpi.crt"
echo "   - Cle privee : /etc/ssl/glpi/glpi.key"
echo

# ---------- 11bis) Distribution de la CA MyCA ----------
echo
echo "[11bis/16] Distribution de votre CA interne MyCA"
echo " Copiez le fichier /etc/ssl/glpi/MyCA.crt sur vos postes clients"
echo " (par exemple avec WinSCP) puis importez le"
echo " dans les autorites de certification racines de confiance."
echo

# ---------- 12) Configuration Nginx HTTP -> HTTPS ----------
clear
echo "[12/16] Configuration Nginx (redirection HTTP vers HTTPS + vhost GLPI)"

if [ -f /etc/nginx/sites-available/default ]; then
    mv /etc/nginx/sites-available/default /etc/nginx/sites-available/default.BAK
fi

cat > /etc/nginx/sites-available/default << EOF
# Redirection HTTP vers HTTPS
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name ${GLPI_HOST};
    return 301 https://${GLPI_HOST}\$request_uri;
}

# VirtualHost HTTPS pour GLPI
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;

    server_name ${GLPI_HOST};

    root /var/www/html/glpi/public;
    index index.php;

    ssl_certificate     /etc/ssl/glpi/glpi.crt;
    ssl_certificate_key /etc/ssl/glpi/glpi.key;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        try_files \$uri \$uri/ /index.php\$is_args\$args;
    }

    location ~ ^/index\.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php${PHP_FPM_VER}-fpm.sock;
        fastcgi_read_timeout 300;
    }

    error_log /var/log/nginx/glpi_error.log;
    access_log /var/log/nginx/glpi_access.log;
}
EOF

echo " - Test configuration Nginx"
if ! nginx -t; then
    echo " [ERREUR] Configuration Nginx invalide."
    exit 1
fi

systemctl reload nginx

# ---------- 13) Installation base GLPI ----------
clear
echo "[13/16] Installation CLI de la base GLPI"
cd /var/www/html/glpi

php ./bin/console db:install \
    --db-host=localhost \
    --db-name="glpidb" \
    --db-user="adminglpi" \
    --db-password="Ertyuiop,64" \
    --no-telemetry \
    --force --no-interaction --allow-superuser

# ---------- 13bis) Changement mots de passe comptes par defaut ----------
clear
echo "[13bis/16] Changement des mots de passe des comptes GLPI par defaut"
echo
read -s -p " Mot de passe commun pour glpi / post-only / tech / normal [TSSR.info@2023] : " NEWPASS
echo
NEWPASS=${NEWPASS:-TSSR.info@2023}

if [ -n "$NEWPASS" ]; then
    export GLPI_NEWPASS="$NEWPASS"
    HASH=$(php -r 'define("GLPI_ROOT","/var/www/html/glpi"); require GLPI_ROOT . "/inc/includes.php"; echo Toolbox::hashPassword(getenv("GLPI_NEWPASS"));')
    if [ -n "$HASH" ]; then
        mysql -uroot glpidb -e "UPDATE glpi_users SET password='${HASH}', password_last_update=NOW() WHERE name IN ('glpi','post-only','tech','normal');"
        echo " - Mots de passe des comptes par defaut mis a jour."
    else
        echo " [AVERTISSEMENT] Impossible de calculer le hash du mot de passe."
    fi
fi

# ---------- 13ter) Desactivation mode demonstration ----------
echo
echo "[13ter/16] Tentative de desactivation du mode demonstration"
mysql -uroot glpidb -e "UPDATE glpi_configs SET value='0' WHERE context='core' AND name IN ('demo_mode','use_preloaded_data','is_demo','demo_data');" 2>/dev/null || true

# ---------- 14) Droits sur les logs ----------
clear
echo "[14/16] Application des droits sur /var/log/glpi"
chown -R www-data:www-data /var/log/glpi

# ---------- 15) Suppression install web ----------
clear
echo "[15/16] Suppression du script d installation web"
rm -f /var/www/html/glpi/install/install.php
systemctl reload nginx

# ---------- 16) Recapitulatif ----------
clear
echo "====================================================="
echo " Installation GLPI 11.0.2 terminee"
echo "====================================================="
echo
echo " URL : https://${GLPI_HOST}/"
echo
echo " Certificats :"
echo "   - CA interne (a importer sur les postes) : /etc/ssl/glpi/MyCA.crt"
echo "   - Certificat site GLPI : /etc/ssl/glpi/glpi.crt"
echo
echo " Comptes par defaut : glpi / post-only / tech / normal"
echo " Mot de passe : celui saisi pendant l installation."
echo
echo " Dossiers importants :"
echo "  - Config : /etc/glpi"
echo "  - Donnees : /var/lib/glpi"
echo "  - Logs    : /var/log/glpi"
echo "  - Code    : /var/www/html/glpi"
echo
echo " Pensez a importer /etc/ssl/glpi/MyCA.crt dans les"
echo " 'Autorites de certification racines de confiance'"
echo " sur vos postes clients pour supprimer l alerte HTTPS."
echo
echo "====================================================="