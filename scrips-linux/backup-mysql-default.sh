
#!/bin/bash
###############################################
# Daily Backup MySQL
# Author Wilton Guilherme
# Year 2017
# dpkg-reconfigure tzdata
# 
###############################################

#VARIAVEIS
DATAHORA=`date +%Y%m%d`
MYSQLDUMP=/usr/bin/mysqldump
MYSQLDIR='/backup/data-bases/'
TAR=/bin/tar
RM=/bin/rm
LOG='/backup/logs'
SENDEMAIL='sh PATH-SENDMAIL'
DATABASE1=''
DATABASE2=''
IPREMOTE=''
DBSERVER='localhost'
PASSWORD=''
ROOT='root'


#Limpando Unidade de Backup
$RM -rf $MYSQLDIR/*

#Realizando backup $DATABASE1

$MYSQLDUMP -h$DBSERVER -u$ROOT --password=$PASSWORD  $DATABASE1 > $MYSQLDIR/$DATABASE1.bkp_$DATAHORA.sql

#Entrando no diretorio de backup

cd $MYSQLDIR

##Compactando o backup
$TAR czvf $DATABASE1.bkp_$DATAHORA.tar.gz $DATABASE1.bkp_$DATAHORA.sql

#Copiando Arquivos

s3cmd put $DATABASE1.bkp_$DATAHORA.tar.gz s3://bucket-path/

#Enviando MSG Backup

$SENDEMAIL
