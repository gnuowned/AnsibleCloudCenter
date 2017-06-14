#!/bin/bash

LOG_FILE='/usr/local/osmosix/logs/config.log'
PG_HBA_FILE='/var/lib/pgsql/9.5/data/pg_hba.conf'
PG_CONF_FILE='/var/lib/pgsql/9.5/data/postgresql.conf'

HA_INFO_FILE='/usr/local/osmosix/etc/pg_ha_info'
HA_ROLE_FILE='/usr/local/osmosix/etc/pg_ha_role'
HA_MARKER_FILE='/usr/local/osmosix/etc/.HAINSTALLED'

INTERACTIVE='false'


umask 022

postgres_user_password="ca\$hc0w"
cliqr_db=cliqrdb

cloud='amazon'
cloud=$(cat /usr/local/osmosix/etc/cloud)

ip_type='vip'

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

  prop_val=`cat $prop_file | grep "^$prop_name=" | cut -d '=' -f 2`

  echo $prop_val
}

##FUNCTION################################################################
# Set a given Name Value info in a property file
#
##########################################################################
Set_Prop_Val()
{
  prop_file=$1
  prop_name="$2"
  prop_val="$3"

  perl -pi -e "s|$prop_name=.*$|$prop_name=$prop_val|" $prop_file
}

##FUNCTION################################################################
# Stop and Disabnle mysql service since db is migrated to postgres
#
##########################################################################
stop_mysql()
{
  for i in $(seq 0 20 60) ; do
      sleep 3
      echo $i | dialog --gauge "Stopping Mysql..." 10 70 0
  done

  type chkconfig >> ${LOG_FILE} 2>&1
  if [[ $? -eq 0 ]]; then
        service mysqld stop >> ${LOG_FILE} 2>&1
        chkconfig mysqld off >> ${LOG_FILE} 2>&1
  fi

  type update-rc.d >> ${LOG_FILE} 2>&1
  if [[ $? -eq 0 ]]; then
        service mysql stop >> ${LOG_FILE} 2>&1
        update-rc.d -f mysql remove >> ${LOG_FILE} 2>&1
  fi
}

##FUNCTION################################################################
# Select dialog for default and echo for non interactive mode
#
##########################################################################
dialog_or_text() {

  dialog_type=$1
  title=$2
  msg=$3
  screen_val1=$4
  screen_val2=$5

  if [[ $INTERACTIVE == "false" ]]; then
    echo "$msg"
  else
    dialog --aspect 80 --title "$title" --$dialog_type "\n\n\n\n\n$msg" $screen_val1 $screen_val2
  fi

}

##FUNCTION################################################################
# Provide postgres db access to the CCM ip provided
#
##########################################################################
Db_Config()
{

  test ! -f "$PG_HBA_FILE" && echo "Postgres config file not present.Aborting" >> $LOG_FILE && dialog --msgbox "\n\n\n\n\n    Postgres Configuration file $PG_HBA_FILE not found Aborting" 15 60 && return

  dialog --aspect 80 --form "Enter CCM IP for Postgres DB Access" 15 60 4 \
        'CCM IP:' 1 1 "$ccm_host" 1 25 20 100 2>/tmp/choice
  if [ $? -ne 0 ]; then
    return
  fi

  dialog --title "Save Confirm" --yesno "\n\n\n\n\n    Do you want to make the changes?" 15 60
  if [ $? -ne 0 ]; then
    return
  fi

  while read lines; do
    ccm_host=$(echo $lines | tr -d '\n')
  done < /tmp/choice

 if [[ $ccm_host ]]; then
    echo "host    all             all             ${ccm_host}/32            trust" >> $PG_HBA_FILE
    dialog_or_text msgbox "Postgres Configuration" "Postgres access configured successfully for the CCM host" 15 60
    service postgresql-9.5 reload
  else
    dialog_or_text msgbox "Postgres Configuration" "Empty hostname provided for CCM host" 15 60
    Db_Config
    return 0
  fi

  return
}

##FUNCTION################################################################
# Configure replication between master and slave
#
##########################################################################
Repl_Config() {


  if [[ -f $HA_ROLE_FILE ]]; then
    dialog_or_text infobox "Replication Configuration" "Replication already configured. Skipping..." 15 60
    sleep 2
    return 0
  fi

  dialog_or_text infobox "Replication Configuration" "Configuring database for replication" 15 60

  export PGPASSWORD=$postgres_user_password
  su postgres -c "psql -d postgres -c \"CREATE ROLE replication WITH REPLICATION PASSWORD 'password' LOGIN;\" "  >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    dialog_or_text msgbox "Replication Configuration" "Failed to create replication role" 15 60
    return 1
  fi

  grep '^wal_level' ${PG_CONF_FILE}
  if [[ $? -ne 0 ]]; then
    echo 'wal_level = hot_standby' >> ${PG_CONF_FILE}
  else
    sed -i "s/^wal_level.*$/wal_level = hot_standby/"  ${PG_CONF_FILE}
  fi

  grep '^max_wal_senders' ${PG_CONF_FILE}
  if [[ $? -ne 0 ]]; then
    echo 'max_wal_senders = 3' >> ${PG_CONF_FILE}
  else
    sed -i "s/^max_wal_senders.*/max_wal_senders = 3/"  ${PG_CONF_FILE}
  fi

  grep '^wal_keep_segments' ${PG_CONF_FILE}
  if [[ $? -ne 0 ]]; then
    echo 'wal_keep_segments = 16' >> ${PG_CONF_FILE}
  else
    sed -i "s/^wal_keep_segments.*$/wal_keep_segments = 16/"  ${PG_CONF_FILE}
  fi

  grep '^max_replication_slots' ${PG_CONF_FILE}
  if [[ $? -ne 0 ]]; then
    echo 'max_replication_slots = 3' >> ${PG_CONF_FILE}
  else
    sed -i "s/^max_replication_slots.*$/max_replication_slots = 3/"  ${PG_CONF_FILE}
  fi

   grep '^hot_standby' ${PG_CONF_FILE}
  if [[ $? -ne 0 ]]; then
    echo 'hot_standby = on' >> ${PG_CONF_FILE}
  else
    sed -i "s/^hot_standby.*$/hot_standby = on/"  ${PG_CONF_FILE}
  fi

  grep  '^host\s\+replication'  ${PG_HBA_FILE}  > /dev/null 2>&1
  if [[ $? -ne 0 ]]; then
    echo 'host    replication     replication     0.0.0.0/0               trust' >> ${PG_HBA_FILE}
  fi

  # Provide access to CCM for access to db
  echo "host    all             all             0.0.0.0/0            trust" >> $PG_HBA_FILE


  service postgresql-9.5 restart  >> ${LOG_FILE} 2>&1

  export PGPASSWORD=$postgres_user_password
  su postgres -c "psql -U postgres -c \"SELECT * FROM pg_create_physical_replication_slot('cliqr_rep_slot1');\" " >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
      dialog_or_text msgbox "Replication Configuration" "Failed to create replication slot" 15 60
      return 1
  fi

# slave
  ssh  ${slave_ip} "(service postgresql-9.5 stop)" >> ${LOG_FILE} 2>&1
  ssh  ${slave_ip} "(rm -rf /var/lib/pgsql/9.5/data/)" >> ${LOG_FILE} 2>&1

  ssh  ${slave_ip} "(sudo -u postgres /usr/pgsql-9.5/bin/pg_basebackup -h ${master_ip} -D /var/lib/pgsql/9.5/data -U replication -v -P --xlog-method=stream)" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    dialog_or_text msgbox "Replication Configuration" "Failed to replicate data from master" 15 60
    return 1
  fi


  recovery_conf_file='/var/lib/pgsql/9.5/data/recovery.conf'
  tmp_recovery_file='/tmp/recovery.conf'
  cat >> ${tmp_recovery_file} << EOL
standby_mode = 'on'
primary_conninfo = 'host=${master_ip} port=5432 user=replication application_name=postgresql-slave keepalives_idle=60 keepalives_interval=5 keepalives_count=5'
restore_command = ''
recovery_target_timeline = 'latest'
primary_slot_name = 'cliqr_rep_slot1'
trigger_file = '/tmp/PSQL-MS.trigger'
EOL

  scp ${tmp_recovery_file} ${slave_ip}:${recovery_conf_file} >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    dialog_or_text msgbox "Replication Configuration" "Failed to copy recovery file from master to slave" 15 60
    return 1
  fi
  rm -f ${tmp_recovery_file}

  ssh  ${slave_ip} "(service postgresql-9.5 restart)" >> ${LOG_FILE} 2>&1
#slave

  ssh  $master_ip "(echo master > ${HA_ROLE_FILE})" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
  	echo "Failed creating ${HA_ROLE_FILE} on ${master_ip}" >> ${LOG_FILE}
	return 1
  fi
  ssh  $slave_ip "(echo slave  > ${HA_ROLE_FILE})" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
  	echo "Failed creating ${HA_ROLE_FILE} on ${slave_ip}" >> ${LOG_FILE}
	return 1
  fi
  return 0
}

##FUNCTION################################################################
# Verify ssh connectivity between hosts
#
##########################################################################
Ssh_Check() {
  host1=$1
  host2=$2

  ssh -o StrictHostKeyChecking=no $host1 id >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  ssh -o StrictHostKeyChecking=no $host2 id >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi
  return 0
}

##FUNCTION################################################################
# Prompt for HA parameters and set the host info in hosts file
#
##########################################################################
Config_HA_Hosts() {

  ip_string='VIP'

  if [[ $cloud == 'amazon' ]]; then
    dialog --radiolist "Select the IP type to use for HA" 15 60 2 VIP 'Virtual IP'  off Elastic 'Elastic IP' off 2> /tmp/choice
    if [[ $? -ne 0 ]]; then
      return 1
    fi
    if [[ ! -s /tmp/choice ]]; then
      dialog_or_text msgbox "Error" "No option selected" 15 60
      return 1
    fi
    ip_choice=$(cat /tmp/choice)

     if [[ ${ip_choice} == 'Elastic' ]]; then
       ip_type=elastic
       ip_string='Elastic IP'
     fi

  fi


  if [[ ! -f $HA_INFO_FILE ]]; then
    touch $HA_INFO_FILE
    echo master_host= >> $HA_INFO_FILE
    echo master_ip=   >> $HA_INFO_FILE
    echo slave_host=   >> $HA_INFO_FILE
    echo slave_ip=   >> $HA_INFO_FILE
    echo ha_vip=   >> $HA_INFO_FILE
  fi

  master_host=$(Get_Prop_Val $HA_INFO_FILE 'master_host')
  master_ip=$(Get_Prop_Val $HA_INFO_FILE 'master_ip')
  slave_host=$(Get_Prop_Val $HA_INFO_FILE 'slave_host')
  slave_ip=$(Get_Prop_Val $HA_INFO_FILE 'slave_ip')
  ha_vip=$(Get_Prop_Val $HA_INFO_FILE 'ha_vip')

  # Hard coding pg master and slave hostnames
  master_host='dbmaster'
  slave_host='dbslave'

#  dialog --aspect 80 --form "Enter Postgres HA info" 15 60 6 \
#        'Master Hostname:' 1 1 "$master_host" 1 25 -30 100 \
#        'Master Private IP:' 2 1 "$master_ip" 2 25 30 100 \
#        'Slave Hostname:' 3 1 "$slave_host" 3 25 -30 100 \
#        'Slave Private IP:' 4 1 "$slave_ip" 4 25 30 100 \
#        "${ip_string} :" 5 1 "$ha_vip" 5 25 30 100  2>/tmp/choice
#  if [ $? -ne 0 ]; then
#    return 1
#  fi

  while read lines; do
    master_ip=$(echo $lines | tr -d '\n')
    read lines
    slave_ip=$(echo $lines | tr -d '\n')
    read lines
    ha_vip=$(echo $lines | tr -d '\n')
  done < /tmp/choice

  Set_Prop_Val $HA_INFO_FILE 'master_host' ${master_host}
  Set_Prop_Val $HA_INFO_FILE 'master_ip' ${master_ip}
  Set_Prop_Val $HA_INFO_FILE 'slave_host' ${slave_host}
  Set_Prop_Val $HA_INFO_FILE 'slave_ip' ${slave_ip}
  Set_Prop_Val $HA_INFO_FILE 'ha_vip' ${ha_vip}

  if [[ ! ${master_host} ]] || [[ ! ${master_ip} ]] || [[ ! ${slave_host} ]] || [[ ! ${slave_ip} ]]; then
  	dialog_or_text msgbox "HA Configuration" "Enter all required values" 15 60
	Config_HA_Hosts
	return $?
  fi

  if [[ ${master_ip} == ${slave_ip} ]] || [[ ${master_host} == ${slave_host} ]]; then
  	dialog_or_text msgbox "Replication Configuration" "Master and Slave cannot have same hostname/ip" 15 60
	Config_HA_Hosts
	return $?
  fi

  Ssh_Check ${master_ip} ${slave_ip}
  if [[ $? -ne 0 ]]; then
  	dialog --msgbox "\nSSH not configured between nodes\nUse the following steps to configure ssh between master and slave\n\nOn Node1\n$ ssh-keygen -t rsa\n cd ~/.ssh\ncat id_rsa.pub >> authorized_keys\n\nCopy the files ~/.ssh/id_rsa and ~/.ssh/id_rsa.pub to the Node2\n\nOn Node2\ncd ~/.ssh\nchmod 400 ~/.ssh/id_rsa*\ncat id_rsa.pub >> authorized_keys\n" 20 80
	return 1
  fi

  echo "${master_ip} ${master_host}" >> /etc/hosts
  echo "${slave_ip} ${slave_host}" >> /etc/hosts

  ssh  $slave_ip "(echo ${master_ip} ${master_host} >> /etc/hosts )" >> ${LOG_FILE} 2>&1
  ssh  $slave_ip   "(echo ${slave_ip} ${slave_host} >> /etc/hosts )" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
  	dialog_or_text msgbox "HA Configuration" "Failed in updating host info in host ${slave_ip}" 15 60
  fi

  return 0
}



##FUNCTION################################################################
# Start PCS service on Master and Slave
#
##########################################################################
PCS_Service_Start() {

  systemctl start pcsd.service >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  ssh  $slave_ip "(systemctl start pcsd.service)" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  systemctl enable pcsd.service  >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  ssh  $slave_ip "(systemctl enable pcsd.service)" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi
  return 0
}

##FUNCTION################################################################
# Change ha user passwd to a predefined password
#
##########################################################################
Change_HAcluster_Pwd() {
  hacluster_pwd='welcome'
  echo $hacluster_pwd  | passwd hacluster --stdin >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  ssh  $slave_ip "(echo $hacluster_pwd  | passwd hacluster --stdin)" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi
  return 0
}

##FUNCTION################################################################
# Start PCS cluster on the master node
#
##########################################################################
PCS_Start() {

  host1=$1
  host2=$2
  # verify authentication between hosts

  setenforce 0

  pcs cluster auth --force $host1 $host2 -u hacluster -p welcome >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  cluster_name='cliqrdbcluster'
  # setup the pacemaker cluster
  pcs cluster setup --force --name ${cluster_name} ${host1} ${host2} >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
   echo "Failed setting up cluster" >> ${LOG_FILE}
   return 2
  fi

  # start the pacemaker cluster
  pcs cluster start --all >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    pcs cluster start --all >> ${LOG_FILE} 2>&1
    if [[ $? -ne 0 ]]; then
       echo "Failed starting cluster" >> ${LOG_FILE}
       return 3
    fi
  fi

  #Disable stonith
  sleep 5
  pcs property set stonith-enabled=false >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    sleep 2
    pcs property set stonith-enabled=false >> ${LOG_FILE} 2>&1
    if [[ $? -ne 0 ]]; then
       echo "Failed disabling  stonith" >> ${LOG_FILE}
       return 4
    fi
  fi

  ssh  -o StrictHostKeyChecking=no ${host2} "(setenforce 0)" >> ${LOG_FILE} 2>&1
  ssh  ${host2} "(pcs property set stonith-enabled=false)" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    sleep 2
    ssh  ${host2} "(pcs property set stonith-enabled=false)" >> ${LOG_FILE} 2>&1
    if [[ $? -ne 0 ]]; then
       echo "Failed disabling  stonith" >> ${LOG_FILE}
       return 5
    fi
  fi
  return 0
}

##FUNCTION################################################################
# Disable postgres system service since pacemaker will manage the service
#
##########################################################################
Disable_Postgres() {

  service postgresql-9.5 restart >> ${LOG_FILE} 2>&1
  sleep 5

  export PGPASSWORD=$postgres_user_password
  su postgres -c "psql -U postgres -c \"SELECT * FROM pg_drop_replication_slot('cliqr_rep_slot1');\" " >> ${LOG_FILE} 2>&1

  service postgresql-9.5 stop >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  ssh  ${slave_ip} "(service postgresql-9.5 stop)" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  chkconfig postgresql-9.5 off >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

  ssh  ${slave_ip} "(chkconfig postgresql-9.5 off)" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 1
  fi

}

##FUNCTION################################################################
# Setup pg password on master and slave
#
##########################################################################
Setup_Pgpass() {

  root_pgpass_file='/root/.pgpass'
  postgre_pgpass_file=~postgres/.pgpass

  echo "*:*:*:postgres:ca\$hc0w" > ${root_pgpass_file}
  chmod 600 ${root_pgpass_file}
  scp ${root_pgpass_file} ${slave_ip}:${root_pgpass_file} >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    dialog_or_text msgbox "HA Configuration" "Failed to copy file $root_pgpass_file to ${slave_ip}" 15 60
    return 1
  fi

  echo "*:*:*:postgres:ca\$hc0w" > ${postgre_pgpass_file}
  chmod 600 ${postgre_pgpass_file}
  scp ${postgre_pgpass_file} ${slave_ip}:${postgre_pgpass_file} >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    dialog_or_text msgbox "HA Configuration" "Failed to copy file $postgre_pgpass_file to ${slave_ip}" 15 60
    return 1
  fi

  chown postgres:postgres ${postgre_pgpass_file}
  ssh ${slave_ip} "(chown postgres:postgres ${postgre_pgpass_file})" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    dialog_or_text msgbox "HA Configuration" "Failed to change ownership of file $postgre_pgpass_file in ${slave_ip}" 15 60
    return 1
  fi
}



##FUNCTION################################################################
# Create and Configure VIP for pacemaker
#
##########################################################################
Configure_PCS_VIP() {
  if [[ $cloud == 'amazon' ]]; then

    if [[ ${ip_type} == vip ]]; then
      config_file='EC2SecIP'
    elif [[ ${ip_type} == 'elastic' ]]; then
      config_file='EC2ElasticIP'
    fi

    pcs resource create EC2SecondaryIP ocf:heartbeat:${config_file} ip=${ha_vip} op monitor interval=120s >> ${LOG_FILE} 2>&1
    if [[ $? -ne 0 ]]; then
      return 1
    fi
  fi

  if [[ ${ip_type} == vip ]]; then
    pcs resource create PGMasterVIP ocf:heartbeat:IPaddr2 ip=${ha_vip} cidr_netmask=32 op monitor interval=30s >> ${LOG_FILE} 2>&1
    if [[ $? -ne 0 ]]; then
      return 2
    fi
  fi


  if [[ $cloud == 'amazon' ]]; then

    if [[ ${ip_type} == 'vip' ]]; then
      pcs resource group add VIPGroup EC2SecondaryIP PGMasterVIP  >> ${LOG_FILE} 2>&1
      if [[ $? -ne 0 ]]; then
       return 3
      fi

      pcs constraint colocation add PGMasterVIP with EC2SecondaryIP INFINITY >> ${LOG_FILE} 2>&1
      if [[ $? -ne 0 ]]; then
       return 4
      fi
    else
      pcs resource group add VIPGroup EC2SecondaryIP >> ${LOG_FILE} 2>&1
      if [[ $? -ne 0 ]]; then
       return 3
      fi
    fi

  else

    pcs resource group add VIPGroup  PGMasterVIP >> ${LOG_FILE} 2>&1
    if [[ $? -ne 0 ]]; then
     return 5
    fi

  fi

   pcs resource defaults resource-stickiness=100 >> ${LOG_FILE} 2>&1
   if [[ $? -ne 0 ]]; then
     return 6
   fi

}


##FUNCTION################################################################
# Create pcs resources
#
##########################################################################
PCS_Resource_Create() {

  master_host=$1
  slave_host=$2
  ha_vip=$3

pcs resource create pgsql pgsql \
   pgctl="/usr/pgsql-9.5/bin/pg_ctl" \
   psql="/bin/psql" \
   pgdata="/var/lib/pgsql/9.5/data/" \
   rep_mode="sync" \
   node_list="${master_host} ${slave_host}" \
   repuser="replication" \
   primary_conninfo_opt="keepalives_idle=60 keepalives_interval=5 keepalives_count=5" \
   master_ip="${ha_vip}" \
   restart_on_promote='true' \
   replication_slot_name='cliqr_rep_slot' \
   op start   timeout="60s" interval="0s"  on-fail="restart" \
   op monitor timeout="60s" interval="4s" on-fail="restart" \
   op monitor timeout="60s" interval="3s"  on-fail="restart" role="Master" \
   op promote timeout="60s" interval="0s"  on-fail="restart" \
   op demote  timeout="60s" interval="0s"  on-fail="stop" \
   op stop    timeout="60s" interval="0s"  on-fail="block" \
   op notify  timeout="60s" interval="0s"  >> ${LOG_FILE} 2>&1
   if [[ $? -ne 0 ]]; then
     return 1
   fi


  sleep 2
  pcs resource master mspostgresql pgsql notify="true"  master-max=1 master-node-max=1 clone-max=2 clone-node-max=1 target-role="Started" >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 2
  fi

  sleep 2
  pcs constraint colocation set VIPGroup role=Started set mspostgresql role=Master setoptions score=INFINITY >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 3
  fi

  sleep 2
  pcs constraint order start VIPGroup then promote mspostgresql symmetrical=false score=INFINITY  >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 4
  fi

  sleep 2
  pcs constraint order stop VIPGroup then demote  mspostgresql symmetrical=false score=INFINITY >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 5
  fi

  sleep 2
  pcs resource cleanup mspostgresql >> ${LOG_FILE} 2>&1
  if [[ $? -ne 0 ]]; then
    return 6
  fi

  return 0

}


##FUNCTION################################################################
# Main HA function which calls all HA subroutines
#
##########################################################################
HA_Config() {

   master_host=''
   master_ip=''
   slave_ip=''
   slave_host=''
   ha_vip=''

   Config_HA_Hosts
   if [[ $? -ne 0 ]]; then
    return 1
   fi

   Repl_Config
   status=$?
   if [[ $status -ne 0 ]]; then
     dialog_or_text msgbox "Error" "Failed in setting up replication for databases with exit code ${status}" 15 60
     return 1
   fi

   sleep 20  # Till we figure a way to reliably wait till replication is complete

  dialog_or_text infobox "HA Configuration" "Configuring database for HA..." 15 60
   PCS_Service_Start
   status=$?
   if [[ $status -ne 0 ]]; then
     dialog_or_text msgbox "Error" "Failed starting PCS service with exit code ${status}" 15 60
     return 1
   fi

   Change_HAcluster_Pwd
   status=$?
   if [[ $status -ne 0 ]]; then
     dialog_or_text msgbox "Error" "Failed setting passwd for hacluster with exit code ${status}" 15 60
     return 1
   fi

   PCS_Start ${master_host} ${slave_host}
   status=$?
   if [[ $status -ne 0 ]]; then
     dialog_or_text msgbox "Error" "Failed starting PCS cluster. Check if SSH is configured between master db and slave db instances with exit code ${status}" 15 60
     return 1
   fi


  Disable_Postgres
   status=$?
   if [[ $status -ne 0 ]]; then
     dialog_or_text msgbox "Error" "Failed disabling postgres service with exit code ${status}" 15 60
     return 1
   fi


  Setup_Pgpass
   status=$?
   if [[ $status -ne 0 ]]; then
     dialog_or_text msgbox "Error" "Failed configuring postgres passwd for pcs with exit code ${status}" 15 60
     return 1
   fi

  Configure_PCS_VIP
   status=$?
   if [[ $status -ne 0 ]]; then
     dialog_or_text msgbox "Error" "Failed configuring VIP for pcs with exit code ${status}" 15 60
     return 1
   fi

  PCS_Resource_Create ${master_host} ${slave_host} ${ha_vip}
   status=$?
   if [[ $status -ne 0 ]]; then
     dialog_or_text msgbox "Error" "Failed creating PCS resource with exit code ${status}" 15 60
     return 1
   fi

  dialog_or_text msgbox "HA Configuration" "Successfully configured database for HA" 15 60
  touch ${HA_MARKER_FILE}
  return 0
}



##FUNCTION################################################################
# User input box to configure HA
#
##########################################################################
Config_Pgsql_HA() {

  dialog  --aspect 80 --menu "DB HA Screen" 15 75 0\
      HA_Config "Configure Postgres HA " 2> /tmp/choice
  if [ $? -ne 0 ]; then
    return 0
  fi
  CHOICE=`cat /tmp/choice`

  if [ "$CHOICE" == "HA_Config" ]; then
    if [[ -f ${HA_MARKER_FILE} ]]; then
      dialog --title "HA Config" --msgbox  "\n\n\n\n\n    HA is already configured on this system" 15 60
      return 0
    fi

    dialog --title "Config Confirm" --yesno "\n\n\n\n\n      Do you want to configure Postgres HA?" 15 60
    if [ $? -ne 0 ]; then
      return 0
    fi
    HA_Config
    rm -f /tmp/choice
  fi

}

##FUNCTION################################################################
# Main dialog box shown at startup
#
##########################################################################
main()
{
  if [[ $EUID -ne 0 ]]; then
    echo "Script should be called with root user. Aborting..."
    exit 1;
  fi


  Check_For_Dialog
  rm -f $LOG_FILE
  dialog_or_text msgbox  "..." "Welcome to Database Configuration Utility" 15 60

  while :
  do
    dialog  --aspect 80 --menu "Main Screen" 15 60 0\
        Configure_HA "Configure Postgres High Availablity"\
        Postgres_Config "Manage Access to Postgres Database" \
        Exit "Exit this utility" 2> /tmp/choice
    if [ $? -ne 0 ]; then
      reset
      exit 0
    fi
    CHOICE=`cat /tmp/choice`

        if [ "$CHOICE" == "Postgres_Config" ]; then
          dialog --aspect 80 --infobox "Configure Postgres Database" 15 60
          Db_Config
          rm -f /tmp/choice
          reset
        fi

        # Not needed for 4.7
        if [ "$CHOICE" == "Stop_Mysql" ]; then
          dialog --aspect 80 --infobox "Disabling Mysql Services" 15 60
	  stop_mysql
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "Configure_HA" ]; then
          dialog --aspect 80 --infobox "Configure Postgres for replication and/or HA" 15 60
 	  Config_Pgsql_HA
          rm -f /tmp/choice
          reset
        fi

        if [ "$CHOICE" == "Exit" ]; then
          rm -f /tmp/choice
          reset
          exit 0
        fi
  done

}

# Init - Program Execution
#main
if [[ -f $HA_MARKER_FILE ]]; then
  echo "The HA configuration was done previously... Exiting..."
  exit 0
fi
HA_Config


exit 0
