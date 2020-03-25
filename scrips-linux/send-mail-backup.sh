#!/bin/sh
###############################################
# Send Mail Administrator Network
# Author Wilton Guilherme CodeView
# Year 2019
###############################################

#Variaveis de ambiente
FROM="r"
TO=""

#Titulo do Email
SUBJECT="Backup $(date "+dia %d de %b de %Y as %r")"

#Montando Corpo do Email

MSG=$(tree -l -h -C -D --charset x /path)
MSG2=$(du -hs /path)

cat <<EOF | /usr/sbin/sendmail -t
From: $FROM
To: $TO
Subject: $SUBJECT

Olá , enviando as tarefas de backups executadas.

Resultado no Backup Local:
$MSG

Tamanho Total do Backup:
$MSG2
________________________________________________________
Script CODEVIEW CONSULTORIA
EOF
#
