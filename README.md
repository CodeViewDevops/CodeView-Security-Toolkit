## CST - CodeView Security Toolkit 
**Baseline** de segurança para sistemas Unix

**CST - CodeView Security Toolkit** É uma ferramenta projetada para auxiliar na implementação de BASELINES de segurança em sistemas operacionais Unix. A ferramenta é composta por uma série de scripts Shell que realiza a correção e aplica regras de segurança em sistemas Linux sem afetar seu funcionamento.
Uma boa parte das correções aplicadas servem como base para auditorias das principais certificações de segurança do mundo como **PCI DSS / CSA**.
A ferramenta foi construída para funcionar nos Sistemas Operacionais AIX, HP-UX, Solaris e Linux (Red Hat, 
CentOS, Debian, Ubuntu) esse  software pode ser usado em outras distribuições com base em sistemas operacionais UNIX, não há nenhuma garantia de funcionamento mas não ira danificar seu sistema operacional se for bem utilizado.
**CST - CodeView Security Toolkit** automaticamente detecta qual Sistema Operacional está instalado e roda as rotinas apropriadas para a versão selecionada.

###  Preparação do Ambiente

A ferramenta deverá ser executada com um usuário que tenha privilégios de root, e também recomendamos que os servidores sejam retardados após as modificações.
Realize o download do repositório no servidor que deseja aplicar as correções, normalmente você deve utilizar este script na preparação de imagens ou servidores estáticos que ficam abertos para internet.

### Usando o CST
Acesse o diretório baixado através do git e execute o script unix corrections.sh. Lembrando que ele deve ser executado com privilégios de super usuário (root):

```
$ git clone git@github.com:CodeViewDevops/cst.git
$ cd cst
$./unix_corrections.sh
```

### ./unix_corrections.sh

**Atenção**No Sistema Operacional Solaris, o shell padrão é incompatível com a ferramenta. Portanto você deve chamá-la usando o shell **sh**
```
$ /usr/xpg4/bin/sh ./unix_corrections.sh
```
Caso todos os passos sejam executados corretamente deverá aparecer uma tela semelhante a abaixo:

```
-----------------------------------------------------------------------------
CST - CodeView Security Toolkit - Version 1.0
-----------------------------------------------------------------------------
Run this script in order to apply security settings previously
Prepare your Server to be audit secutity with scipt CodeView
(c) Copyright (c) 2020 CodeView Consultoria, All Rights Reserved
------------------------------------------------------------------------------
Options:

  [1] Baseline             (Not Defined)
  [2] Set Interactivity    (yes)
  [3] Change Log File      (/var/security/backup/date/sessionlog)
  [4] Backup               (/var/security/backup/03012020-17:25:43)
  [5] Restore Backup
  [6] Avaliable Routines
  [7] Ignored Routines
  [8] Apply Corrections
  [9] Services
  [10] Help
  [11] Exit
  
Choose option:
```
 Opções da Ferramenta
----------------------
- **1. Baseline**
Nessa opção, você poderá escolher o baseline que será aplicado no servidor, A ferramenta já vem com todos os baselines definidos para o servidor escolhido. Caso não exista o baseline para server que você deseja aplicar você pode abrir uma issue e informar o que precisa ou contribuir com nosso projeto que é aberto a comunidade. 

- **2. Set Intractivity**
Com essa opção setada (YES) a ferramenta de correção pede a confirmação de todos os itens a serem aplicados. Caso contrário, todos os itens serão aplicados quando usar a opção 8 (Apply Corrections).

-  **3. Change Log File**
Essa opção é referente ao destino do arquivo de log. Por padrão ele salva o arquivo de log com o nome sessionlog no diretório de backup.

- **4. Backup**
Seta o diretório onde serão salvas as alterações feitas no sistema. A cada execução do script é criada uma
sessão de backup.

- **5. Restore Backup**
Restaura as alterações de uma sessão do script.

- **6. Avaliable Routines**
Lista todos os itens que serão aplicados. Não aplica nenhum item.

- **7. Ignored Routines**
Lista todos os itens que o script não aplicará.

- **8. Apply Corrections**
Aplica os itens selecionados de acordo com o baseline selecionado.

- **9. Services**
Essa opção serve para aplicar correção aos serviços rodando na máquina. Os baselines são escolhidos separadamente.

- **10. Help**
Mostrar as principais funcionalidades das funções da ferramenta de correção Unix.

- **11. Exit**
Finaliza o script.

## Incompatibilidades
Eventualmente, o script rodando em Sun(Solaris) poderá informar que o shell não é comparável, então irá
mostrar uma mensagem na tela explicando como proceder neste caso, mas normalmente poderia executar o script assim:
```
 /usr/xpg4/bin/sh ./unix_corrections.sh
```
### Observações Finais
Os itens abaixo não são aplicados com o script, pois são dependentes de instalação, são eles:
- TCP Wrappers
- Patches de segurança
