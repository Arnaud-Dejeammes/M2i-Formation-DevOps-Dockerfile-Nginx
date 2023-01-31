FROM nginx

RUN rm /etc/nginx/nginx.conf /etc/nginx/conf.d/default.conf \

&& docker config create

&& apt-get install fcgiwrap \
&& /usr/sbin/fcgiwrap -s unix:/fcgiwrap.socket
chmod 666
&& start fcgiwrap

# https://docs.docker.com/engine/swarm/configs/
# Création d'une root key
&& openssl genrsa -out "root-ca.key" 4096
# Création d'un CSR (certificate signing request) à partir de la root key
RUN openssl req \
-new -key "root-ca.key" \
-out "root-ca.csr" -sha256 \
-subj ' /C=US/ST=CA/L=San Francisco/O=Docker/CN=Swarm Secret Example CA'

ARG
ARG

ENTRYPOINT my_scrypt agr1 arg2



&& [root_ca]

ADD . .dockerignore

COPY content /usr/share/nginx/html
COPY conf /etc/nginx

COPY index.html /usr/share/nginx/html

COPY ./default.conf /etc/nginx/conf.d/default.conf
COPY ./includes/ /etc/nginx/includes/
COPY ./ssl/ /etc/ssl/certs/nginx

openssl
# TLS
# http https
# location .cgi$ fcgiwrap

    location ~ \.cgi$ {
        include fcgiwrap_params;
	# include fastcgi_params;
        fastcgi_param DOCUMENT_ROOT /var/www/cgi-bin/;
	# fastcgi_param SCRIPT_NAME myscript.cgi;
	fastcgi_param SCRIPT_NAME main.cgi;	
        fastcgi_pass unix:/run/fcgiwrap.socket;

VOLUME ["/etc/nginx/sites-enabled", "/etc/nginx/certs", "/etc/nginx/conf.d", "/var/log/nginx", "/var/www/html"]

WORKDIR /etc/nginx

CMD start nginx

EXPOSE 80

# COPY certificates
ssl_certificate /etc/ssl/certs/nginx.crt;
ssl_certificate_key /etc/ssl/private/nginx.key;
# TLS
# Mise en place d'un serveur TLS
server {
    # Ajout de ssl et http2 comme directive d'écoute    
	listen 443 ssl http2;
	server_name TLS_server_001;
	root /var/www/html/TLS_server_001;
    # ln -s /etc/nginx/sites-available/TLS_server_001 /etc/nginx/sites-enabled
    index TLS_server_001.html;
	# Permet de changer le paramètre par défaut (index.html). Dans /var/www/html/TLS_server_001
    # SSL et anciennes versions de TLS à écarter
git    ssl_protocols TLSv1.3;

    ssl_prefer_server_ciphers on;
    # Suite de chiffrement
    ssl_ciphers 
    ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DH+3DES:!ADH:!AECDH:!MD5;
    # ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;

    # Génération des paramètres Diffie–Hellman
    ##########################################
    # $ > openssl dhparam -out filename 2048 #
    ##########################################
    # openssl dhparam 2048 -out /etc/nginx/certs/dhparam.pem
    # ou
    # openssl dhparam -out /etc/nginx/dhparam.pem 4096
    # Ajuster les certificat TLS et les paramètres DH (2048 minimum, 4096...)

    # Paramètres DH (DH Params - Diffie-Hellman): clef d'échange   
    # ssl_dhparam /etc/nginx/certs/dhparam.pem; # mkdir certs 
    ssl_dhparam /etc/nginx/filename;
    
    ##################################################### -----
    # Génération d'une demande de signature d'un certificat
    # openssl req -new -sha256 -key private_key -out filename

    # Génération d'un certificat autosigné
    # openssl req -key private_key -x509 -new -days days -out filename

    # Generate a self-signed certificate with private key in a single command
    # openssl req -x509 -newkey rsa:2048 -days days -keyout key_filename -out cert_filename
    ##################################################### -----    
    
    ############################################################################################################################
    # $ > openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx.key -out /etc/ssl/certs/nginx.crt #
    ############################################################################################################################
    ssl_certificate /etc/ssl/certs/nginx.crt; # OK

    ssl_certificate_key /etc/ssl/private/nginx.key;  # Inexistant

    # Configuration dans un fichier snippet à inclure dans le bloc serveur Nginx
    ##############################################
    # touch /etc/nginx/snippets/self-signed.conf #
    ##############################################
    # ssl_protocols TLSv1.2;
    # ssl_prefer_server_ciphers on;
    # ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    # ssl_session_timeout 10m;
    # ssl_session_cache shared:SSL:10m;
    # ssl_session_tickets off;
    # ssl_stapling on;
    # ssl_stapling_verify on;
    # resolver 8.8.8.8 8.8.4.4 valid=300s;
    # resolver_timeout 5s;
    # add_header X-Frame-Options DENY;
    # add_header X-Content-Type-Options nosniff;
    # add_header X-XSS-Protection "1; mode=block";

    # ssl_dhparam /etc/nginx/dhparam.pem;
    # ssl_ecdh_curve secp384r1;

# # User directories, e.g. http://example.com/~user/ # Permet de ne pas utiliser adduser
# location ~ ^/~(.+?)(/.*)?$ { # Regex
#   alias     /home/$1/public_html$2; # Le fichier doit exister
#   index     index.html index.htm;
#   autoindex on;
# }

# Per-user directories
    location ~ ^/~(.+?)(/.*)?$ {
    alias /var/www/html/$1/public_html$2;
    index index.html index.htm;
    autoindex on;
    # + droit et mot de passe

    # CGI : Différence entre Arch Linux et Ubuntu !!!
    # Page d'essai
    # CGI : deux lignes obligatoires : shebang et html (cf. screenshot)
   

    }

    ########################################################################
    # https://www.nginx.com/resources/wiki/start/topics/examples/fcgiwrap/ #
    ########################################################################
    # fast cgi support
    # include /etc/nginx/fcgiwrap.conf;

    location ~ \.cgi$ {
        include fcgiwrap_params;
	# include fastcgi_params;
        fastcgi_param DOCUMENT_ROOT /var/www/cgi-bin/;
	# fastcgi_param SCRIPT_NAME myscript.cgi;
	fastcgi_param SCRIPT_NAME main.cgi;	
        fastcgi_pass unix:/run/fcgiwrap.socket;
}


    error_log /var/log/nginx/TLS_server_001.error.log;
    access_log /var/log/nginx/TLS_server_001.access.log;
