#!/bin/bash

LOG_FILE='/usr/local/cliqr/logs/config.log'
MAIL_FILE='/usr/local/tomcat/webapps/ROOT/WEB-INF/mail.properties'
SERVER_FILE='/usr/local/tomcat/webapps/ROOT/WEB-INF/server.properties'
MGMT_FILE='/usr/local/tomcat/webapps/ROOT/WEB-INF/mgmt.properties'
RABBIT_CONFIG_FILE="/usr/local/osmosix/bin/rabbit_config.sh"
ESB_FILE='/usr/local/tomcat/webapps/cliqr-esb/WEB-INF/esb.properties'
DB_FILE='/usr/local/tomcat/webapps/ROOT/WEB-INF/db.properties'
FLYWAY_CONF="/usr/local/flyway/conf/flyway.conf"

HAROLE_FILE='/usr/local/osmosix/etc/harole'

umask 022

##FUNCTION################################################################
#  Check if dialog utility exists 
##########################################################################
Check_For_Dialog() 
{
  type dialog  > /dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo "Dialog utility not found. Quitting"
    exit 1
  fi
}

##FUNCTION################################################################
#  Parse a property file and figure out if a Name exists
# 
##########################################################################
Get_Prop_Val() 
{
  prop_file=$1
  prop_name=$2

  prop_val=`cat $prop_file | grep "^$prop_name=" | cut -d '=' -f 2-`
  	
  echo $prop_val
}

##FUNCTION################################################################
# Set a given Name Value info in a property file
# 
##########################################################################
Set_Prop_Val() 
{
  prop_file="$1"
  prop_name="$2"
  prop_val=$(echo $3 | sed 's/@/\\@/g')
  prop_val=$(echo $prop_val | sed 's/\$/\\$/g')

  perl -pi -e "s|$prop_name=.*$|$prop_name=$prop_val|" $prop_file	
}

##FUNCTION################################################################
# Encrypt user provided string 
#    - used for mail password
##########################################################################
Encrypt_String() {
  config_dir='/usr/local/osmosix/lib/com/osmosix/misc/config'

  commons_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/osmosix-commons-[0-9]*.jar)
  commons_io_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/commons-io-*.jar)
  log4_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/log4j-[0-9]*.jar)
  slf_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/slf4j-api-[0-9]*.jar)
  slf_log4_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/slf4j-log4j*.jar)
  aws_java_sdk=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/aws-java-sdk-core-[0-9]*.jar)
  aws_s3_sdk=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/aws-java-sdk-s3-[0-9]*.jar)
  google_http_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/google-http-client-[0-9]*.jar)
  google_jackson_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/google-http-client-jackson-[0-9]*.jar)
  codec_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/commons-codec-[0-9]*.jar)
  commons_lang=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/commons-lang3-[0-9].*.jar)

  encrypt_string=$(java -cp ${commons_jar}:${commons_io_jar}:${log4_jar}:${slf_log4_jar}:${slf_jar}:${aws_java_sdk}:${aws_s3_sdk}:${google_http_jar}:${google_jackson_jar}:${codec_jar}:${commons_lang}:${config_dir} EncryptMe $1 2>/dev/null)

}

##FUNCTION################################################################
# Encrypt user provided string 
#    - used for db password
##########################################################################
Encrypt_String2() {
  config_dir='/usr/local/osmosix/lib/com/osmosix/misc/config'

  commons_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/osmosix-commons-[0-9]*.jar)
  slf_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/slf4j-api-[0-9]*.jar)
  codec_jar=$(ls -1 /usr/local/tomcat/webapps/ROOT/WEB-INF/lib/commons-codec-[0-9]*.jar)

  encrypt_string=$(java -cp ${commons_jar}:${slf_jar}:${codec_jar}:/usr/local/osmosix/lib  com/osmosix/misc/config/ConfigUtility $1 2>/dev/null)
}

##FUNCTION################################################################
# Set DB related parameters
#    - db host
##########################################################################
DB_Config()
{

  test ! -f "$DB_FILE" && echo "DB properties file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    DB Configuration file $DB_FILE not found Aborting" 15 60 && return

  db_host=$(Get_Prop_Val $DB_FILE 'database.postgres.host') 
  db_user=$(Get_Prop_Val $DB_FILE 'database.postgres.username') 


  old_db_host=${db_host}

  dialog --aspect 80 --form "Enter DB Parameters" 15 60 3 \
	'DB IP or Hostname:' 1 1 "$db_host" 1 25 50 120 \
	'DB Username:' 2 1 "$db_user" 2 25 50 120 \
	'DB Password:' 3 1 "####" 3 25 50 120 2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  dialog --title "Save Confirm" --yesno "\n\n\n\n\n   Do you want to make the changes?" 15 60 
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    db_host=$(echo $lines | tr -d '\n')
    read lines
    db_user=$(echo $lines | tr -d '\n')
    read lines
    db_pass=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  if [[ ${db_host} != ${old_db_host} ]]; then

    new_db_pass=${db_pass} 
    if [[ ${db_pass} == '####' ]]; then
      new_db_pass='cliqr'
    fi
 
    sed -i  "s?\(flyway.url=jdbc:postgresql://\).*\(:5432\)?\1$db_host\2?" ${FLYWAY_CONF}
    sed -i  "s?^flyway.user=.*?flyway.user=${db_user}?" ${FLYWAY_CONF}
    sed -i  "s?^flyway.password=.*?flyway.password=${new_db_pass}?" ${FLYWAY_CONF}

    dialog --title "Config Confirm" --yesno "\n\n\n\n\n               Database host changed.\n Do you want to run flyway migrate with the new database host?" 15 60
    if [ $? -eq 0 ]; then
      dialog --aspect 80 --infobox "\n\n\n\n\n       Running Flyway Migrate..." 15 60
      /usr/local/flyway/flyway migrate >> ${LOG_FILE} 2>&1
      if [[ $? -ne 0 ]]; then
        dialog --msgbox "\n\n\n\n\n  Failed running flyway migrate on ${db_host}. Ensure that proper hostname / username / password are provided" 15 60
        return 1
      fi
    fi
  
  fi

  if [[ ${db_pass} != '####' ]]; then
      sed -i  "s?^flyway.password=.*?flyway.password=${db_pass}?" ${FLYWAY_CONF}
      encrypt_string=""
      Encrypt_String2 ${db_pass}
      db_pass=${encrypt_string}
      Set_Prop_Val $DB_FILE 'database.postgres.password' ${db_pass}
  fi
  sed -i  "s?^flyway.user=.*?flyway.user=${db_user}?" ${FLYWAY_CONF}
  Set_Prop_Val $DB_FILE 'database.postgres.username' ${db_user}
  Set_Prop_Val $DB_FILE 'database.postgres.host' ${db_host}

  dialog --title "DB Parameters Config" --msgbox  "\n\n\n\n\n    Configured parameters to connect to DB.\nNote: Ensure that the database is configured with the same parameters" 15 60 

}


##FUNCTION################################################################
# Set mail related parameters
#    - smtp host, smtp port, smtp auth
##########################################################################
Mail()
{

  test ! -f "$MAIL_FILE" && echo "Mail config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    Mail Configuration file $MAIL_FILE not found Aborting" 15 60 && return

  smtp_host=$(Get_Prop_Val $MAIL_FILE 'mail.smtp.host') 
  smtp_port=$(Get_Prop_Val $MAIL_FILE 'mail.smtp.port')
  smtp_auth=$(Get_Prop_Val $MAIL_FILE 'mail.smtp.auth') 

  dialog --aspect 80 --form "Enter Mail Parameters" 15 60 3 \
	'Smtp Host:' 1 1 "$smtp_host" 1 15 30 60 \
	'Smtp Port:' 2 1 "$smtp_port" 2 15 30 60 \
 	'Smtp Auth:' 3 1 "$smtp_auth" 3 15 30 0  2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  dialog --title "Save Confirm" --yesno "\n\n\n\n\n   Do you want to make the changes?" 15 60 
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    smtp_host=$(echo $lines | tr -d '\n')
    read lines
    smtp_port=$(echo $lines | tr -d '\n')
    read lines
    smtp_auth=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  Set_Prop_Val $MAIL_FILE 'mail.smtp.host' ${smtp_host} 
  Set_Prop_Val $MAIL_FILE 'mail.smtp.port' ${smtp_port} 
  Set_Prop_Val $MAIL_FILE 'mail.smtp.auth' ${smtp_auth}

  dialog --title "Mail Parameters Config" --msgbox  "\n\n\n\n\n    Configured Mail parameters successfully" 15 60 

}

##FUNCTION################################################################
# Set mail user related parameters
#    - mail user, mail password, from user, from name
##########################################################################
MailUser()
{

  test ! -f "$MAIL_FILE" && echo "Mail config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    Mail Configuration file $MAIL_FILE not found Aborting" 15 60 && return

  mail_user=$(Get_Prop_Val $MAIL_FILE 'mail.user.1') 
  mail_pwd=$(Get_Prop_Val $MAIL_FILE 'mail.password.1')
  from_user=$(Get_Prop_Val $MAIL_FILE 'from.mail.user.1') 
  from_name=$(Get_Prop_Val $MAIL_FILE 'from.mail.username.1') 

  mail_old_pwd="$mail_pwd"
  mail_pwd=$(echo $mail_pwd | sed 's/[<>]//g')

  dialog --aspect 80 --form "Enter Mail User Parameters" 15 60 4 \
	'Mail User:' 1 1 "$mail_user" 1 15 30 60 \
	'Password:' 2 1 "$mail_pwd" 2 15 30 60 \
 	'From User:' 3 1 "$from_user" 3 15 30 60  \
 	'Display Name:' 4 1 "$from_name" 4 15 30 60  2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  dialog --title "Save Confirm" --yesno "\n\n\n\n\n    Do you want to make the changes?" 15 60 
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    mail_user=$(echo $lines | tr -d '\n')
    read lines
    mail_new_pwd=$(echo $lines | tr -d '\n')
    read lines
    from_user=$(echo $lines | tr -d '\n')
    read lines
    from_name=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  if [[ ${mail_new_pwd} == ${mail_pwd} ]]; then
	echo "No change to mail password"
  else
    mail_new_pwd=$(echo $mail_new_pwd | sed 's/[<>]//g')
    encryption_type=$(cat /usr/local/osmosix/etc/encryption)
    if [[ ${encryption_type} == "nss" ]]; then 	
      encrypt_string=""
      Encrypt_String ${mail_new_pwd}
      mail_new_pwd=${encrypt_string}
    else
      mail_new_pwd='<'${mail_new_pwd}'>'
    fi
    Set_Prop_Val $MAIL_FILE 'mail.password.1' "${mail_new_pwd}"
  fi

  Set_Prop_Val $MAIL_FILE 'mail.user.1' ${mail_user}
  Set_Prop_Val $MAIL_FILE 'from.mail.user.1' ${from_user}
  Set_Prop_Val $MAIL_FILE 'from.mail.username.1' ${from_name}

  dialog --title "Mail Parameters Config" --msgbox  "\n\n\n\n\n   Configured Mail User parameters successfully" 15 60 
  return 
}


##FUNCTION################################################################
# Set ccm server related parameters
#    - server dns, monitor url, hazelcast ip, external url
##########################################################################
Server_Info()
{

  test ! -f "$SERVER_FILE" && echo "Server config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    Server Configuration file $SERVER_FILE not found Aborting" 15 60 && return

  server_dns=$(Get_Prop_Val $SERVER_FILE 'publicDnsName') 
  monitor_url=$(Get_Prop_Val $SERVER_FILE 'monitorBaseUrl')
  hazelcast_ip=$(Get_Prop_Val $SERVER_FILE 'hazelcastIPList') 
  outface_dns=$(Get_Prop_Val $SERVER_FILE 'outfaceDnsName') 

  dialog --aspect 80 --form "Enter Server Parameters" 15 60 4 \
	'Public DNS:' 1 1 "$server_dns" 1 15 30 100 \
	'Monitor URL:' 2 1 "$monitor_url" 2 15 30 100 \
 	'Hazelcast IP:' 3 1 "$hazelcast_ip" 3 15 30 100  \
 	'External URL:' 4 1 "$outface_dns" 4 15 30 100  2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  dialog --title "Save Confirm" --yesno "\n\n\n\n\n    Do you want to make the changes?" 15 60 
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    server_dns=$(echo $lines | tr -d '\n')
    read lines
    monitor_url=$(echo $lines | tr -d '\n')
    read lines
    hazelcast_ip=$(echo $lines | tr -d '\n')
    read lines
    outface_dns=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  Set_Prop_Val $SERVER_FILE 'publicDnsName' ${server_dns}
  Set_Prop_Val $SERVER_FILE 'monitorBaseUrl' ${monitor_url}
  Set_Prop_Val $SERVER_FILE 'hazelcastIPList' ${hazelcast_ip}
  Set_Prop_Val $SERVER_FILE 'outfaceDnsName' ${outface_dns}

  dialog --title "Server Parameters Config" --msgbox  "\n\n\n\n\n   Configured Server parameters successfully" 15 60 
  return 
}

##FUNCTION################################################################
# Set logstash related parameters
#    - Logstash info, elastic search info, kibana info
##########################################################################
ELK_Info()
{

  test ! -f "$SERVER_FILE" && echo "Server config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    Server Configuration file $SERVER_FILE not found Aborting" 15 60 && return

  elastic_host=$(Get_Prop_Val $SERVER_FILE 'ccm.log.elkHost')
  elastic_port=$(Get_Prop_Val $SERVER_FILE 'ccm.log.elasticSearchPort')
  logstash_port=$(Get_Prop_Val $SERVER_FILE 'ccm.log.logStashPort')
  kibana_port=$(Get_Prop_Val $SERVER_FILE 'ccm.log.kibanaPort')
  elastic_user=$(Get_Prop_Val $SERVER_FILE 'ccm.log.elasticSearchUserName')
  elastic_pass=$(Get_Prop_Val $SERVER_FILE 'ccm.log.elasticSearchPassword')
  host_identifier=$(Get_Prop_Val $SERVER_FILE 'ccm.log.host.identifier')
  hahost_identifier=$(Get_Prop_Val $SERVER_FILE 'ccm.log.haHostIdentifierList')

  if [[ ! $host_identifier ]]; then 
    host_identifier=ccm_$(date +%s)
  fi

  dialog --aspect 80 --form "Enter ELK Parameters" 15 60 8 \
	'ELK host:' 1 1 "$elastic_host" 1 25 30 100 \
	'Elasticsearch port:' 2 1 "$elastic_port" 2 25 30 100 \
 	'Logstash port:' 3 1 "$logstash_port" 3 25 30 100  \
 	'Kibana port:' 4 1 "$kibana_port" 4 25 30 100  \
 	'ELK user:' 5 1 "$elastic_user" 5 25 30 100  \
 	'ELK password:' 6 1 "####" 6 25 30 100  \
 	'Host Identifier:' 7 1 "$host_identifier" 7 25 30 100  \
 	'Host Identifier List:' 8 1 "$hahost_identifier" 8 25 30 100  2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  dialog --title "Save Confirm" --yesno "\n\n\n\n\n    Do you want to make the changes?" 15 60 
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    elastic_host=$(echo $lines | tr -d '\n')
    read lines
    elastic_port=$(echo $lines | tr -d '\n')
    read lines
    logstash_port=$(echo $lines | tr -d '\n')
    read lines
    kibana_port=$(echo $lines | tr -d '\n')
    read lines
    elastic_user=$(echo $lines | tr -d '\n')
    read lines
    elastic_pass=$(echo $lines | tr -d '\n')
    read lines
    host_identifier=$(echo $lines | tr -d '\n')
    read lines
    hahost_identifier=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  if [[ ${elastic_pass} != '####' ]]; then
      encrypt_string=""
      Encrypt_String ${elastic_pass}
      elastic_pass=${encrypt_string}
      Set_Prop_Val $SERVER_FILE 'ccm.log.elasticSearchPassword' ${elastic_pass}
  fi

  Set_Prop_Val $SERVER_FILE 'ccm.log.elkHost' ${elastic_host}
  Set_Prop_Val $SERVER_FILE 'ccm.log.elasticSearchPort' ${elastic_port}
  Set_Prop_Val $SERVER_FILE 'ccm.log.logStashPort' ${logstash_port}
  Set_Prop_Val $SERVER_FILE 'ccm.log.kibanaPort' ${kibana_port}
  Set_Prop_Val $SERVER_FILE 'ccm.log.elasticSearchUserName' ${elastic_user}
  Set_Prop_Val $SERVER_FILE 'ccm.log.host.identifier' ${host_identifier}
  Set_Prop_Val $SERVER_FILE 'ccm.log.haHostIdentifierList' ${hahost_identifier}

  dialog --title "ELK Parameters Config" --msgbox  "\n\n\n\n\n   Configured ELK parameters successfully" 15 60 
  return 
}

##FUNCTION################################################################
# Set cLoud package URL
#    
##########################################################################
Mgmt_Info()
{

  test ! -f "$MGMT_FILE" && echo "Mgmt config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    Mgmt Configuration file $MGMT_FILE not found Aborting" 15 60 && return

  cloud_package=$(Get_Prop_Val $MGMT_FILE 'cloud.packages.url') 

  dialog --aspect 80 --form "Enter Management Parameters" 15 60 2 \
 	'Cloud Package URL:' 1 1 "$cloud_package" 1 15 30 60  2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  dialog --title "Save Confirm" --yesno "\n\n\n\n\n    Do you want to make the changes?" 15 60 
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    cloud_package=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  Set_Prop_Val $MGMT_FILE 'cloud.packages.url' $cloud_package

  dialog --title "Mgmt Parameters Config" --msgbox  "\n\n\n\n\n   Configured Management parameters successfully" 15 60 
  return 
}


##FUNCTION################################################################
# Restart tomcat server. Display a progress bar while restarting
#    
##########################################################################
Restart_Server()
{

  /etc/init.d/tomcat stop > /dev/null 2>&1  &
  for i in $(seq 0 20 100) ; do 
    sleep 3 
    echo $i | dialog --gauge "Restart server..." 10 70 0
  done
  ps -ef | grep  '/usr/local/tomcat' | awk '{print $2}' | xargs kill -9 > /dev/null 2>&1
  /etc/init.d/tomcat start  > /dev/null 2>&1

}

##FUNCTION################################################################
# Restart tomcat on remote node. Fails if non root user is used and 
#    if user does not have sudo access to run command
##########################################################################
Restart_Remote_Server()
{
  remote_ip=$1
  ssh_user=$2

  sudo_string=''
  su_string=''
  if [[ ${ssh_user} != "root" ]]; then
     sudo_string='sudo -u root' 
     fail_msg="\n  User $ssh_user may not have sudo permission for root"
      su_string="sudo -u $ssh_user"
  fi

  $su_string ssh $ssh_user@$remote_ip $sudo_string /etc/init.d/tomcat stop > /dev/null 2>&1  
  sleep 5
  $su_string ssh $ssh_user@$remote_ip $sudo_string /etc/init.d/tomcat start > /dev/null 2>&1  
  if [[ $? -ne 0 ]]; then
     dialog --msgbox "\n\n\n\n\n  Failed restarting tomcat on ${remote_ip}. ${fail_msg}\n  Restart tomcat manually on instance  ${remote_ip}" 15 60
  fi

  return 0
}


##FUNCTION################################################################
# Set host related info on the instance
#    - set ip , hostname and fqdn in hosts file
##########################################################################
Config_Hostname() 
{

  dialog --aspect 80 --form "Enter Hostname Info" 15 60 4 \
	'IP address:' 1 1 "127.0.0.1" 1 17 30 100 \
	'Hostname (FQDN):' 2 1 "" 2 17 30 100 \
 	'Hostname:' 3 1 "" 3 17 30 60  2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi


  while read lines; do
    ip_address=$(echo $lines | tr -d '\n')
    read lines
    fqdn=$(echo $lines | tr -d '\n')
    read lines
    hname=$(echo $lines | tr -d '\n')
  done < /tmp/choice


  if [[ ! $hname ]]; then
    dialog --msgbox "\n\n\n\n\n  Hostname cannot be empty  " 15 60 	
    Config_Hostname	
  fi 

  dialog --title "Save Confirm" --yesno "\n\n\n\n\n    Do you want to configure the hostname? \n  Hostname : $hname \n  FQDN: $fqdn \n  IP : $ip_address " 15 60 
  if [ $? -ne 0 ]; then
    return
  fi

  echo "$ip_address $fqdn $hname " >> /etc/hosts
  if [[ $? -ne 0 ]]; then
     dialog --msgbox "\n\n\n\n\n  Failed updating hosts file" 15 60
     return 1
  fi  
  
  dialog --title "Network Parameters Config" --msgbox  "\n\n\n\n\n   Configured Hostname successfully" 15 60 
  return 

}

##FUNCTION################################################################
# List possible network interfaces to be selected for configuration
#    
##########################################################################
Select_Interface()
{

  interface_list=$(/sbin/ifconfig -s | awk '{print $1}')
  valid_ifc=""
  for ifc in  $interface_list; do
    if [[ $ifc == 'Iface' ]] || [[ $ifc == 'lo' ]]; then
      continue
    fi
    valid_ifc="$ifc Interface"  
  done 

  dialog  --aspect 80 --menu "Interface Screen" 15 60 0\
      $valid_ifc 2> /tmp/choice
  if [ $? -ne 0 ]; then
    return 0
  fi
  CHOICE=`cat /tmp/choice`

  Config_Interface $CHOICE 
    
}


##FUNCTION################################################################
# Display option to set selected network interface to static / dhcp
#    
##########################################################################
Config_Interface()
{
  ifc_name=$1
  IFC_FILE='/etc/network/interfaces'
  if [[ ! -f $IFC_FILE ]]; then
     dialog --msgbox "\n\n\n\n\nNetwork Interface file $IFC_FILE not found" 15 60
     return 1
  fi

  IFC_SEP_FILE='/etc/network/interfaces.d/'${ifc_name}'.cfg'
  if [[ -f $IFC_FILE ]]; then
     IFC_FILE=${IFC_SEP_FILE}
  fi

  dialog  --aspect 80 --menu "Network Screen" 15 60 0\
      DHCP "Set interface to DHCP" \
      Static_IP "Set Static IP for interface"  2> /tmp/choice
  if [ $? -ne 0 ]; then
    return 0
  fi
  CHOICE=`cat /tmp/choice`


  if [ "$CHOICE" == "DHCP" ]; then
     dialog --title "Confirm" --yesno "\n\n\n\n\n   Do you want to set the interface to DHCP?" 15 60 
     if test $? -eq 0; then
       rm -f /tmp/choice
       Set_Static_DHCP $IFC_SEP_FILE $ifc_name dhcp
     else
       return 0
     fi
  fi

  if [ "$CHOICE" == "Static_IP" ]; then
    dialog --aspect 80 --form "Enter Static IP Info" 15 60 4 \
	'IP address:' 1 1 "$ip" 1 15 30 60 \
	'Gateway IP:' 2 1 "$gwip" 2 15 30 60 \
 	'Netmask:' 3 1 "$netmask" 3 15 30 0  \
 	'Name Servers:' 4 1 "$dnsnames" 4 15 60 0  2>/tmp/choice2
    if [ $? -ne 0 ]; then
      return
    fi

    dialog --title "Confirm" --yesno "\n\n\n\n\n   Do you want to set the specified values to interface $ifc_name?" 15 60 
    if test $? -eq 0; then
      rm -f /tmp/choice
      Set_Static_DHCP $IFC_SEP_FILE $ifc_name static /tmp/choice2
    else
      return 0
    fi
  fi
  
}


##FUNCTION################################################################
# Set the selected interface to Either Static or DHCP based on user opt
#    
##########################################################################
Set_Static_DHCP()
{
  filename=$1
  interface=$2
  option=$3
  choice_file=$4

  if [[ $option == "static" ]]; then
    while read lines; do
      ip=$(echo $lines | tr -d '\n')
      read lines
      gwip=$(echo $lines | tr -d '\n')
      read lines
      netmask=$(echo $lines | tr -d '\n')
      read lines	
      dnsnames=$(echo $lines | tr -d '\n')
    done < $choice_file
  fi
  rm $choice_file

  if [[ ! $ip ]] ||  [[ ! $gwip ]] || [[ ! $netmask ]]; then
    dialog --title "Interface Config" --msgbox  "\n\n\n\n\n   IP , Gateway IP and Netmask cannot be empty " 15 60 
    return 1
  fi
  set_ip_exec="/usr/local/osmosix/bin/set_interface.pl"

  perl $set_ip_exec $filename $interface $option $ip $gwip $netmask "$dnsnames"
  if [[ $? -ne 0 ]]; then
    dialog --title "Interface Config" --msgbox  "\n\n\n\n\n    Failed configuring interface" 15 60 
    return 1
  fi

  dialog --title "Interface Config" --msgbox  "\n\n\n\n\n    Successfully configured interface $interface" 15 60 

  service networking restart >>  $LOG_FILE 2>&1
  service resolvconf restart >>  $LOG_FILE 2>&1

}


##FUNCTION################################################################
# Display option for Network and Host configuration
#    
##########################################################################
Network() {
  dialog  --aspect 80 --menu "Network Screen" 15 60 0\
      Hostname "Configure Hostname" 2> /tmp/choice
#      Interface "Configure Interface"  2> /tmp/choice
  if [ $? -ne 0 ]; then
    return 0
  fi
  CHOICE=`cat /tmp/choice`

  if [ "$CHOICE" == "Hostname" ]; then
    dialog --aspect 80 --infobox "Configuring Hostname" 15 60
    Config_Hostname
    rm -f /tmp/choice
  fi

  if [ "$CHOICE" == "Interface" ]; then
    dialog --aspect 80 --infobox "Configuring Interface" 15 60
    Select_Interface
    rm -f /tmp/choice
  fi

}


##FUNCTION################################################################
# Execute rabbit_config file for configuring AMQP for ESB
#    
##########################################################################
Config_Rabbit() {

  rabbit_log="/tmp/rabbit_config.log"
  test ! -f "$RABBIT_CONFIG_FILE" && echo "Rabbit config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    RabbitMQ Configuration file $RABBIT_CONFIG_FILE not found Aborting" 15 60 && return
  test ! -f "$ESB_FILE" && echo "ESB config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    ESB Configuration file $ESB_FILE not found Aborting" 15 60 && return

  $RABBIT_CONFIG_FILE >> ${rabbit_log} 2>&1
  if [[ $? -ne 0 ]]; then
     dialog --msgbox "\n\n\n\n\n  Failed executing $RABBIT_CONFIG_FILE. Check file ${rabbit_log} for details." 15 60
     return 1 
  fi

  rm -f ${rabbit_log}
  dialog --msgbox "\n\n\n\n\n  RabbitMQ configured successfully for ESB." 15 60
  return 0
}

##FUNCTION################################################################
# Set ESB related parameters
#    - set rabbit host,port, notification server, trust pwd,keystore passwd
##########################################################################
Configure_ESB_Params()
{

  test ! -f "$ESB_FILE" && echo "ESB config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    ESB Configuration file $ESB_FILE not found Aborting" 15 60 && return

  rabbit_host=$(Get_Prop_Val $ESB_FILE 'rabbit.esb.brokerHost') 
  rabbit_port=$(Get_Prop_Val $ESB_FILE 'rabbit.esb.brokerPort')
  mgmt_addr=$(Get_Prop_Val $ESB_FILE 'mgmt.address') 
  notsrv_addr=$(Get_Prop_Val $ESB_FILE 'notification.server.address') 
  trust_pwd=$(Get_Prop_Val $ESB_FILE 'truststore.password') 
  keystr_pwd=$(Get_Prop_Val $ESB_FILE 'keystore.password') 

  dialog --aspect 80 --form "Enter ESB Parameters" 15 60 6 \
	'Rabbit Host:' 1 1 "$rabbit_host" 1 25 30 60 \
	'Rabbit Port:' 2 1 "$rabbit_port" 2 25 30 60 \
 	'CCM IP:' 3 1 "$mgmt_addr" 3 25 30 60  \
 	'Notification Server IP:' 4 1 "$notsrv_addr" 4 25 30 60 \
 	'Truststore password:' 5 1 "$trust_pwd" 5 25 30 60  \
 	'Keystore password:' 6 1 "$keystr_pwd" 6 25 30 60  2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  dialog --title "Save Confirm" --yesno "\n\n\n\n\n    Do you want to make the changes?" 15 60 
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    rabbit_host=$(echo $lines | tr -d '\n')
    read lines
    rabbit_port=$(echo $lines | tr -d '\n')
    read lines
    mgmt_addr=$(echo $lines | tr -d '\n')
    read lines
    notsrv_addr=$(echo $lines | tr -d '\n')
    read lines
    trust_pwd=$(echo $lines | tr -d '\n')
    read lines
    keystr_pwd=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  Set_Prop_Val $ESB_FILE 'rabbit.esb.brokerHost' ${rabbit_host}
  Set_Prop_Val $ESB_FILE 'rabbit.esb.brokerPort' ${rabbit_port}
  Set_Prop_Val $ESB_FILE 'mgmt.address' ${mgmt_addr}
  Set_Prop_Val $ESB_FILE 'notification.server.address' ${notsrv_addr}
  Set_Prop_Val $ESB_FILE 'truststore.password' ${trust_pwd}
  Set_Prop_Val $ESB_FILE 'keystore.password' ${keystr_pwd}

  dialog --title "ESB Parameters Config" --msgbox  "\n\n\n\n\n   Configured ESB User parameters successfully" 15 60 
  return 
}



##FUNCTION################################################################
# Display options for ESB configuration
#    
##########################################################################
ESB_Info() {
  test ! -f "$ESB_FILE" && echo "ESB config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    ESB Configuration file $ESB_FILE not found Aborting" 15 60 && return 1

  dialog  --aspect 80 --menu "ESB Screen" 15 60 0\
      RabbitConfig "Configure RabbitMQ for ESB" \
      ESB_Config "Configure ESB props"  2> /tmp/choice
  if [ $? -ne 0 ]; then
    return 0
  fi
  CHOICE=`cat /tmp/choice`

  if [ "$CHOICE" == "RabbitConfig" ]; then
    if [[ -f "/usr/local/osmosix/etc/.RABBITINSTALLED" ]]; then
      dialog --title "Rabbit Config" --msgbox  "\n\n\n\n\n    RabbitMQ is already configured on this system" 15 60
      return 0
    fi
    
    dialog --title "Config Confirm" --yesno "\n\n\n\n\n   Do you want to configure rabbit for esb?" 15 60 
    if [ $? -ne 0 ]; then
      return 0
    fi
    dialog --aspect 80 --infobox "Configuring RabbitMQ for ESB" 15 60
    Config_Rabbit
    rm -f /tmp/choice
  fi

  if [ "$CHOICE" == "ESB_Config" ]; then
    dialog --aspect 80 --infobox "Configuring ESB parameters" 15 60
    Configure_ESB_Params
    rm -f /tmp/choice
  fi

}

##FUNCTION################################################################
# Query DB and configure app logo directories to names specified in db
#    
##########################################################################
configure_applogo() {
  test ! -f "$DB_FILE" && echo "db.properties file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    Configuration file $DB_FILE not found Aborting" 15 60 && return 1

  SQL_OUTPUT='/tmp/applogodir.out'
  VENDOR_SQL='/tmp/vendorchg.sql'
  rm -f $SQL_OUTPUT
  rm -f $VENDOR_SQL

  db_host=$(Get_Prop_Val $DB_FILE 'database.postgres.host') 
  db_user=$(Get_Prop_Val $DB_FILE 'database.postgres.username') 

  dialog --aspect 80 --form "Enter DB Password" 15 60 1 \
	'DB Password:' 1 1 "" 1 25 50 120 2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    db_pass=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  if [[ $db_host != 'localhost' ]]; then
    db_host_str='-h '${db_host}
  else
   db_host_str=''
  fi

  export PGPASSWORD=${db_pass}
  psql ${db_host_str} -U ${db_user} -d cliqrdb  -c "select template_id,name from cliqr.ALL_TEMPLATES where template_type='PATTERN';" > $SQL_OUTPUT

  cd /usr/local/tomcat/webapps/ROOT/assets/img/appLogo
  while read line; do
    id=$(echo $line | awk '{print $1}' )
    logo_dir_name=$(echo $line | tr -s ' ' | tr '[A-Z]' '[a-z]' | cut -d '|' -f 2- | tr ' ' '_' | sed s/^_// )
    if [[ -d $logo_dir_name ]]; then
      if [[ -d $id ]]; then
        rm -fr $id >> ${LOG_FILE}
      fi
      mv $logo_dir_name $id  >> ${LOG_FILE} 2>&1
    fi
  done < $SQL_OUTPUT

  rm -f $SQL_OUTPUT
  rm -f $VENDOR_SQL
  return 0
}

##FUNCTION################################################################
# Display confirmation screen for configuring App logo
#    
##########################################################################
Config_App_Logo() {
    
    dialog --title "Config Confirm" --yesno "\n\n\n\n\n   Do you want to reconfigure app logos?" 15 60 
    if [ $? -ne 0 ]; then
      return 0
    fi

    dialog --aspect 80 --infobox "Configuring App Logo" 15 60
    configure_applogo  	
    if [[  $? == 0 ]]; then 
      dialog --title "Config App Logo" --msgbox  "\n\n\n\n     App logos configured successfully." 15 60
    fi
    rm -f /tmp/choice
    return 0	
}


##FUNCTION################################################################
# Configure CCM HA across instances 
#   - check for ssh connectivity between nodes
#   - create ha role file with master/slave on both instances 
#   - add a cron job for unison in this instance
#   - modify server.prop file and copy to remote instance
#   - restart tomcat on both instances
##########################################################################
HA_Config() {
  prim_ip=$1
  sec_ip=$2
  ssh_user=$3
  server_dns=$4
  hazelcast_ip=$5
  outface_dns=$6


  dialog --aspect 80 --infobox "\n\n\n\n\n  Configuring CCM HA..." 15 60
  su_string=''
  if [[ $ssh_user != 'root' ]]; then
    su_string="sudo -u $ssh_user"
  fi

  $su_string ssh  $ssh_user@$host1  "(echo master > ${HAROLE_FILE})" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
  	echo "Failed creating ${HAROLE_FILE} on $host1" >> ${LOG_FILE}
	return 1
  fi
  $su_string ssh  $ssh_user@$host2  "(echo slave  > ${HAROLE_FILE})" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
  	echo "Failed creating ${HAROLE_FILE} on $host2" >> ${LOG_FILE}
	return 1
  fi
 
  if [[ ${ssh_user} == 'cliqruser' ]];then
  	unison_prf_dir='/home/cliqruser/.unison'
  	unison_prf='/home/cliqruser/.unison/default.prf'	

  	cronstring="*/5 * * * * cliqruser /usr/bin/unison >/dev/null 2>&1"
        echo "$cronstring" >> /etc/cron.d/asset_sync

  	Unison_Config ${unison_prf_dir} ${unison_prf} ${sec_ip}
  	chown cliqruser:cliqruser ${unison_prf_dir} ${unison_prf} 
  else
  	unison_prf_dir='/root/.unison'
  	unison_prf='/root/.unison/default.prf'	

  	cronstring="*/5 * * * * /usr/bin/unison >/dev/null 2>&1"
        echo "$cronstring" >> /etc/cron.d/asset_sync

  	Unison_Config ${unison_prf_dir} ${unison_prf} ${sec_ip}
  fi

  Set_Prop_Val $SERVER_FILE 'publicDnsName' ${server_dns}
  Set_Prop_Val $SERVER_FILE 'hazelcastIPList' ${hazelcast_ip}
  Set_Prop_Val $SERVER_FILE 'outfaceDnsName' ${outface_dns}
  $su_string scp $SERVER_FILE $ssh_user@$host2:$SERVER_FILE >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
  	echo "Failed copying ${SERVER_FILE} to $host2"  >> ${LOG_FILE}
	return 1
  fi
   
  Restart_Server
  Restart_Remote_Server ${host2} ${ssh_user}
  
  return 0
}


##FUNCTION################################################################
# Create unison configuration file and asset sync file
#    - create logrorate file for unison logs 
##########################################################################
Unison_Config() {

  unison_prf_dir=$1
  unison_prf=$2
  sec_ip=$3
 
  mkdir ${unison_prf_dir}
  cat > ${unison_prf} <<EOL
# ROOTS
root = /usr/local/
root = ssh://${sec_ip}//usr/local/
 
# DIRS
path = apache-tomcat-8.0.29/webapps/ROOT/assets/img
path = apache-tomcat-8.0.29/webapps/ROOT/assets/vendors
path = apache-tomcat-8.0.29/webapps/ROOT/WEB-INF/vendor
path = osmosix/metadata
 
# IGNORES
ignore = Path .git
 
# SSH ARGS
# sshargs=-p 4000
 
# OTHER OPTS
auto = true
batch = true
fastcheck = true
owner = true
prefer = newer
silent = true
times = true
 
# LOGGING
log = true
logfile = /usr/local/osmosix/logs/unison_sync.log 
EOL

  cat  >  /etc/logrotate.d/asset_sync <<LOGROT
/usr/local/osmosix/logs/unison_sync.log {
missingok
notifempty
daily
rotate 7
compress
sharedscripts
copytruncate
}
LOGROT

}

##FUNCTION################################################################
# Get info related to CCM HA configuration
#   - primary ip, secondary ip,public dns, hazelcast ip,external url
##########################################################################
HA_Get_Info() {

  test ! -f "$SERVER_FILE" && echo "Server config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    Server Configuration file $SERVER_FILE not found Aborting" 15 60 && return

  server_dns=$(Get_Prop_Val $SERVER_FILE 'publicDnsName') 
  hazelcast_ip=$(Get_Prop_Val $SERVER_FILE 'hazelcastIPList') 
  outface_dns=$(Get_Prop_Val $SERVER_FILE 'outfaceDnsName') 
  
  dialog --aspect 80 --form "Enter HA Info" 15 60 5 \
	'Primary Node Private IP:' 1 1 "" 1 28 30 100 \
	'Secondary Node Private IP:' 2 1 "" 2 28 30 100 \
	'Public DNS:' 3 1 "$server_dns" 3 28 30 100 \
 	'Hazelcast IP:' 4 1 "$hazelcast_ip" 4 28 30 100  \
 	'External URL:' 5 1 "$outface_dns" 5 28 30 100  2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    prim_ip=$(echo $lines | tr -d '\n')
    read lines
    sec_ip=$(echo $lines | tr -d '\n')
    read lines
    server_dns=$(echo $lines | tr -d '\n')
    read lines
    hazelcast_ip=$(echo $lines | tr -d '\n')
    read lines
    outface_dns=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  id cliqruser > /dev/null 2>&1
  if [[ $? -eq 0 ]];then
	 ssh_user=cliqruser 
  else
	  ssh_user=root
  fi

  Ssh_Check ${prim_ip} ${sec_ip} ${ssh_user}
  if [[ $? -ne 0 ]]; then
  	dialog --msgbox "\nSSH not configured between nodes\nUse the following steps to configure ssh between master and slave\n\nOn Node1\n$ ssh-keygen -t rsa\n cd ~/.ssh\ncat id_rsa.pub >> authorized_keys\n\nCopy the files ~/.ssh/id_rsa and ~/.ssh/id_rsa.pub to the Node2\n\nOn Node2\ncd ~/.ssh\nchmod 400 ~/.ssh/id_rsa*\ncat id_rsa.pub >> authorized_keys\n" 20 80 
	return 1
  fi

  HA_Config ${prim_ip} ${sec_ip} ${ssh_user} ${server_dns} ${hazelcast_ip} ${outface_dns}
  if [[ $? -ne 0 ]]; then
    dialog --title "CCM HA Config" --msgbox  "\n\n\nFailed to configure CCM HA. \nCheck logfile /usr/local/osmosix/log/config.log  for info" 15 70
  fi

  dialog --title "CCM HA Config" --msgbox  "\n\n\nConfigured CCM HA successfully." 15 70
  return 0
}

##FUNCTION################################################################
# Check if SSH connectivity works between nodes
#    
##########################################################################
Ssh_Check() {
  host1=$1
  host2=$2
  ssh_user=$3	

  su_string=''
  if [[ $ssh_user != 'root' ]]; then
    su_string="sudo -u $ssh_user"
  fi

  $su_string ssh -o StrictHostKeyChecking=no $ssh_user@$host1 id >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  $su_string ssh -o StrictHostKeyChecking=no $ssh_user@$host2 id >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi
  return 0
}


##FUNCTION################################################################
# Confirmation screen for HA config
#    
##########################################################################
Config_CCM_HA() {

  dialog  --aspect 80 --menu "CCM HA Screen" 15 60 0\
      CCM_HA_Config "Configure HA" 2> /tmp/choice
  if [ $? -ne 0 ]; then
    return 0
  fi
  CHOICE=`cat /tmp/choice`

  if [ "$CHOICE" == "CCM_HA_Config" ]; then
    if [[ -f ${HAROLE_FILE} ]]; then
      dialog --title "HA Config" --msgbox  "\n\n\n\n\n    HA is already configured on this system" 15 60
      return 0
    fi
    
    dialog --title "Config Confirm" --yesno "\n\n\n\n\n     Do you want to configure HA on CCM?" 15 60 
    if [ $? -ne 0 ]; then
      return 0
    fi

    HA_Get_Info
    if [[ $? -ne 0 ]]; then
      dialog --title "CCM HA Config" --msgbox  "\n\n\nFailed to configure CCM HA. \nCheck logfile /usr/local/osmosix/log/config.log  for info" 15 70
    fi
    rm -f /tmp/choice
  fi

}

##FUNCTION################################################################
# Main Screen to display all options
#    
##########################################################################
main()
{

  Check_For_Dialog
  # rm -f $LOG_FILE
  dialog --aspect 80 --msgbox "\n\n\n\n\n    Welcome to Server Config Utility" 15 60
  while :
  do
    dialog  --aspect 80 --menu "Main Screen" 15 60 0\
        Mail "Configure Mail Settings" \
        Mail_User "Configure Mail User Info" \
        Server_Info "Configure Server Info"\
	Config_App_Logo "Configure App Logos"\
        ESB_Info "Configure ESB Info"\
        Network "Configure Network"\
        DB "Configure Database"\
        Configure_HA "Configure CCM High Availablity"\
        ELK_Info "Configure ELK Info"\
        Exit "Exit this utility" 2> /tmp/choice
    if [ $? -ne 0 ]; then
      reset	
      exit 0
    fi
    CHOICE=`cat /tmp/choice`

        if [ "$CHOICE" == "Mail" ]; then
          dialog --aspect 80 --infobox "Configuring Mail Parameters" 15 60
          Mail
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "Mail_User" ]; then
          dialog --aspect 80 --infobox "Configuring Mail User Parameters" 15 60
          MailUser
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "Server_Info" ]; then
          dialog --aspect 80 --infobox "Configuring Server Parameters" 15 60
          Server_Info
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "ESB_Info" ]; then
          dialog --aspect 80 --infobox "Configuring ESB Parameters" 15 60
          ESB_Info
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "DB" ]; then
          dialog --aspect 80 --infobox "Configuring DB Parameters" 15 60
          DB_Config
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "Mgmt_Info" ]; then
          dialog --aspect 80 --infobox "Configuring Management Parameters" 15 60
          Server_Info
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "Network" ]; then
          dialog --aspect 80 --infobox "Configuring Network Parameters" 15 60
          Network
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "Config_App_Logo" ]; then
          dialog --aspect 80 --infobox "Configure App Logo" 15 60
          Config_App_Logo 
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "Configure_HA" ]; then
          dialog --aspect 80 --infobox "Configure High Availability" 15 60
          Config_CCM_HA
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "ELK_Info" ]; then
          dialog --aspect 80 --infobox "Configuring ELK Parameters" 15 60
          ELK_Info
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "Exit" ]; then
          dialog --title "Exit Confirm" --yesno "\n\n\n\n\n   Do you want to restart the server?" 15 60 
          if test $? -eq 0; then
            rm -f /tmp/choice
            Restart_Server
            reset
            exit 0
          elif test $? -gt 0; then
            rm -f /tmp/choice
            reset
            exit 0
          fi
        fi
  done

}


# Program  Init
main

exit 0
