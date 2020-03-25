#!/bin/bash
###############################################
# Daily Backup PostgreSQL
# Author Wilton Guilherme - CodeView Consultoria
# Year 2017
###############################################

#VARIAVEIS
DATAHORA=`date +%Y%m%d`
PGSQLDIR='/home/'
TAR=/bin/tar
RM=/bin/rm
LOG='/home/logs'
PGUSER='postgres'
SENDEMAIL='sh /srv/script/mail.sh'
DATABASE1=''
DATABASE2=''
IPREMOTE=''
DBSERVER=''

#Limpando Unidade de Backup
#$RM -rf $PGSQLDIR/*

#Realizando backup $DATABASE1

pg_dump -Ft -U $PGUSER -f $DATABASE1\-$DATAHORA.tar $DATABASE1

#Entrando no diretorio de backup

cd $PGSQLDIR

##Compactando o backup
$TAR czvf $DATABASE1\-$DATAHORA.tar.gz $DATABASE1\-$DATAHORA.tar

#Copiando Arquivos

s3cmd put $DAT$DATABASE1\-$DATAHORA.tar.gz s3://bucket

#Enviando MSG Backup

$SENDEMAIL
