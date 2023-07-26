#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/pi

#check_hw_8.5_cvsa_rev02  ver.8.5 14-12-2022

#----- HW instalado ---------------------
# PCB UMAN xxxxxxx
RPI_HUB="Linux Foundation"
PCB_HUB="Genesys Logic"
WIFI_MODUL="Realtek Semiconductor Corp"
WIFI_MODUL_DRIVER="rtl8821au"

GSM_MODEM="ZTE WCDMA Technologies"		
#GSM_MODEM="Huawei Technologies"

WIFI_ENABLE="1"
WLAN0_WPA_CLI_CHECK_ENABLE="1"

GSM_ENABLE="0"
GSM_DISABLE_INTERNET_ACCESS="0"

log_file="/home/pi/HW_error_cvsa_8.5.rev01.txt"
stats_file="/home/pi/hw_stats_cvsa_8.5.rev01"
WLAN0_STATS_FILE="/home/pi/check_hw_cvsa_8.5.rev01_wlan0_stats.txt"
log_poweroff_file="/home/pi/DEBUG_POWER_OFF.dbg"


reinicio_cada_x_no_detect_hub_rpi=2
id_cada_x_min=3
reinicio_cada_x_no_detecciones=20
reinicio_cada_x_no_conexiones=20
desconexion_cada_x_sin_conectividad=6

WLAN1_N_CONNECT_MAX_1=4     #   wlan1 max. consecutive connection attempts (to Wifi1/wlan0); USB Wifi adapter hard reset
WLAN1_N_CONNECT_MAX_2=12    #   wlan1 max. consecutive connection attempts (to Wifi1/wlan0); PCB HUB hard reset
WLAN1_N_CONNECT_MAX_3=16    #   wlan1 max. consecutive connection attempts (to Wifi1/wlan0); Raspberry Pi hard reset


r1="connected"
r2="Failed"			#"Failed to connect"
r3="register"		#"Modem unable to register a network"
r4="capabilities"	#"Device did not report GSM capabilities"

function CREATE_LOG_FILE ()
{
	if [ ! -f $1 ]; then

		sudo echo "$1 file does not exists. creating new file"
		sudo touch $1
		sudo chmod 777 $1
		sudo echo "0" > $1
		date=$(date +"%Y-%m-%d %H:%M:%S")
		sudo sed -i "1s/.*/File created on: $date/" $1

	else

		echo "$1 file already exists."

	fi
}

function CREATE_WLAN_STATS_FILE ()
{
	if [ ! -f $1 ]; then

	sudo echo "$1 file does not exists. creating new file"
	sudo touch $1
	sudo chmod 777 $1
	sudo echo "0" > $1
	date=$(date +"%s-%m-%Y %H:%M:%S")
	sudo sed -i "1s/.*/File created on: $date/" $1

	else

		echo "$1 file already exists."

	fi
}

function CREATE_STATS_FILE ()
{
	if [ ! -f $1 ]; then
		echo "$1 file does not exists. creating new file"
		sudo touch $1
		sudo chmod 777 $1
		wait
		sudo echo -e 	0'\n'0'\n'0'\n'0'\n'0'\n'\'0'\n' > $1
	else 
		echo "$1 file already exists"
	fi
}

function RESET_RPI
{
	sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' chek_hw ejecutara un reboot'\n' >> $log_poweroff_file
	echo -ne '\xFE\xAA' | nc -w1 127.1.1.1 10666
	sleep 2
	sudo reboot now
}

function RELOAD_RPI_HUB
{
	sudo echo '1-1' | sudo tee /sys/bus/usb/drivers/usb/unbind
	sleep 3
	sudo echo '1-1' | sudo tee /sys/bus/usb/drivers/usb/bind
}

function RELOAD_PCB_HUB
{
	sudo gpio mode 23 out
	sudo gpio write 23 1
	sleep 2
	sudo gpio write 23 0
	sleep 5
}

function RELOAD_MODULOS_WIFI
{
	sudo gpio mode 24 out
	sudo gpio mode 27 out
	sudo gpio write 24 0
	sudo gpio write 27 0
	sleep 2
	sudo gpio write 24 1
	sudo gpio write 27 1
	sleep 5
}

function RELOAD_MODULO_WIFI1_WLAN0
{
	sudo gpio mode 27 out
	sudo gpio write 27 0
	sleep 2
	sudo gpio write 27 1
	sleep 5
}

function RELOAD_MODULO_WIFI2_WLAN2
{
	sudo gpio mode 24 out
	sudo gpio write 24 0
	sleep 2
	sudo gpio write 24 1
	sleep 5
}

function RELOAD_WIFI_WIFI1_WLAN0_SW
{
	sudo service hostapd stop
	sudo service isc-dhcp-server stop
	sudo ifconfig wlan0 192.168.42.1 netmask 255.255.255.0 broadcast 192.168.42.255
	sudo service isc-dhcp-server start
	sudo service hostapd start
	sleep 5
}

function RELOAD_GSM_MODEM
{
	sudo gpio mode 25 out
	sudo gpio write 25 0
	sleep 2
	sudo gpio write 25 1
	sleep 20
}

function SEND_ID ()
{
   	serie=$(grep 'SERIE' /home/pi/UMAN_BLUE | sed 's/^.*= //')
	faena=$(grep 'FAENA' /home/pi/UMAN_BLUE | sed 's/^.*= //')
	result=$(ifconfig $1 | grep -oE "\baddr:([0-9]{1,3}\.){3}[0-9]{1,3}\b")
	date=$(date +"%Y-%m-%d %H:%M:%S")
	respuesta="$(echo $serie,$faena,$'\n'local $result'\n'$date | nc -w7 200.6.115.67 10002 2>&1 &)"
	respuesta="$(echo $serie,$faena,$'\n'local $result'\n'$date | nc -w7 201.236.97.74 10002 2>&1 &)"

	sudo echo -e send id '\t\t'$(date +"%Y-%m-%d %H:%M:%S.%3N")  >> /home/pi/USB/LogOperacionRpi.txt

	if [ $respuesta == "OK" ]; then
		sshpass -p 'blc2017imasd' ssh -t -t -f -R 2222:localhost:22 -o StrictHostKeyChecking=no imasd@201.236.97.74 sleep 20
	fi
}

function RELOAD_INTERFACE ()
{
	sudo ifconfig $1 down --f
	sleep 1
	sudo ifconfig $1 up --f
    sleep 1
}


CREATE_LOG_FILE $log_file
CREATE_STATS_FILE $stats_file 
CREATE_WLAN_STATS_FILE $WLAN0_STATS_FILE


action=0

script_lock=`head -1 $line $stats_file | tail -1`
n_no_hub_rpi=`head -2 $line $stats_file | tail -1`

if [ $script_lock -eq "1" ]; then
	script_lock=0
	sudo sed -i "1s/.*/$script_lock/" $stats_file
	exit 0
else
	script_lock=1
	sudo sed -i "1s/.*/$script_lock/" $stats_file
fi


usb_list=$(sudo lsusb)
usb_num=$(sudo echo "$usb_list" | wc -l)
if [ $usb_num -lt 3 ]; then

	sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' HUB RPI no detectado'\n' >> $log_file
	sudo echo -e "$usb_list"'\n' >> $log_file

	n_no_hub_rpi=$((n_no_hub_rpi + 1))
	sudo sed -i "2s/.*/$n_no_hub_rpi/" $stats_file

	reinicio=$(expr $n_no_hub_rpi % $reinicio_cada_x_no_detect_hub_rpi)
	if [ $reinicio -eq 0 ]; then

		echo -e Alcanzadas "$n_no_hub_rpi" no detecciones HUB RPI consecutivas  >> $log_file
		sudo echo -e Se ejecutara un reinicio de RPI >> $log_file

		sudo echo -e ------------------------------------------------------------------------------------------------------------ >> $log_file

		RESET_RPI

	else

		sudo echo -e Cantidad de no detecciones HUB RPI consecutivas: "$n_no_hub_rpi" >> $log_file
		sudo echo -e Se procede a intentar re-detecion de HUB RPI'\n' >> $log_file
		RELOAD_RPI_HUB
		sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Resultado re-deteccion HUB RPI'\n' >> $log_file
		lsusb >> $log_file
	fi

	sudo echo -e ------------------------------------------------------------------------------------------------------------ >> $log_file

	exit 0

else

	if [ $n_no_hub_rpi -ne "0" ]; then
		n_no_hub_rpi=0
		sudo sed -i "2s/.*/$n_no_hub_rpi/" $stats_file
	fi
fi


pcb_hub=$(sudo echo "$usb_list" | grep "$PCB_HUB" | wc -l)
if [ $pcb_hub -ne 1 ]; then

	sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' HUB PCB no detectado'\n' >> $log_file
	sudo echo -e "$usb_list"'\n' >> $log_file
	sudo echo -e Se procede a intentar re-detecion de HUB RPI'\n' >> $log_file
	RELOAD_PCB_HUB
	sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Resultado re-deteccion HUB PCB'\n' >> $log_file
	usb_list=$(sudo lsusb)
	sudo echo -e "$usb_list"'\n' >> $log_file

	action=1
fi


if [ "$WIFI_ENABLE" == "1" ]; then

	s_host=$(service hostapd status | grep "running" | wc -l)
	s_isc_dhcp_server=$(service isc-dhcp-server status | grep "running" | wc -l)
    if [ $s_host -ne 1 ]; then
        
        sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Wifi1/wlan0 hostapd service not running'\n' >> $log_file
		sudo service hostapd status | >> $log_file
        sudo echo "Proceding to restart hostapd service" >> $log_file
		sudo service hostapd restart
		action=1
    fi
    if [ $s_isc_dhcp_server -ne 1 ]; then

        sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Wifi1/wlan0 isc-dhcp-server service not running'\n' >> $log_file
		sudo service isc-dhcp-server status >> $log_file
        sudo echo "Proceding to restart isc_dhcp_server service" >> $log_file
        sudo service isc-dhcp-server stop
		sudo ifconfig wlan0 192.168.42.1 netmask 255.255.255.0 broadcast 192.168.42.255
		sudo service isc-dhcp-server start
		action=1
    fi

	wifi_modul=$(sudo echo "$usb_list" | grep "$WIFI_MODUL" | wc -l)
	if [ $wifi_modul -ne 2 ]; then

		sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' SE DETECTAN "$wifi_modul" MODULOS WIFI'\n' >> $log_file	
		sudo echo -e "$usb_list"'\n' >> $log_file

		if [ $wifi_modul -eq 0 ]; then

			sudo echo -e Se procede a intentar re-deteccion de ambos modulos wifi'\n' >> $log_file
			RELOAD_MODULOS_WIFI
			sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Resultado re-deteccion modulos wifi'\n' >> $log_file
			lsusb >> $log_file
			sudo echo -e '\n'Se procede a reiniciar red WIFI UB >> $log_file
			RELOAD_WIFI_WIFI1_WLAN0_SW

		else
			ports_wifi_modul=$(sudo lsusb -t | grep "$WIFI_MODUL_DRIVER" )
			sudo echo -e "$ports_wifi_modul"'\n' >> $log_file

			wifi1_wlan0=$(echo "$ports_wifi_modul" | grep "Port 4" | wc -l)
			if [ $wifi1_wlan0 -eq 0 ]; then

				sudo echo -e Se procede a intentar re-deteccion de modulo wifi1-wlan0'\n' >> $log_file
				RELOAD_MODULO_WIFI1_WLAN0
				sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Resultado re-deteccion modulo wifi1-wlan0'\n' >> $log_file
				lsusb >> $log_file
				sudo echo -e '\n'Se procede a reiniciar red WIFI UB >> $log_file
				RELOAD_WIFI_WIFI1_WLAN0_SW

			else
				sudo echo -e Se procede a intentar re-deteccion de modulo wifi2-wlan2'\n' >> $log_file
				RELOAD_MODULO_WIFI2_WLAN2
				sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Resultado re-deteccion modulo wifi2-wlan2'\n' >> $log_file
				lsusb >> $log_file
			fi
		fi
		action=1
	fi


	interface_list=$(sudo ifconfig)
	wlan_num=$(sudo echo "$interface_list" | grep -E "wlan0|wlan1|wlan2" | wc -l)
	if [ $wlan_num -ne 3 ]; then

		sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' SE DETECTAN "$wlan_num" INTERFACES WLAN ACTIVAS'\n' >> $log_file
		sudo echo -e "$interface_list"'\n' >> $log_file

		wlan0=$(sudo echo "$interface_list" | grep "wlan0" | wc -l)
		wlan1=$(sudo echo "$interface_list" | grep "wlan1" | wc -l)
		wlan2=$(sudo echo "$interface_list" | grep "wlan2" | wc -l)

		if [ $wlan0 -ne 1 ]; then

			sudo echo -e Interface wlan0 no detectada'\n' >> $log_file
			sudo echo -e Se procede a racargar wlan0'\n' >> $log_file
			RELOAD_INTERFACE wlan0
            sudo ifconfig wlan0 192.168.42.1
		fi

		if [ $wlan1 -ne 1 ]; then

			sudo echo -e Interface wlan1 no detectada'\n' >> $log_file
			sudo echo -e Se procede a racargar wlan1'\n' >> $log_file
			RELOAD_INTERFACE wlan1
		fi

		if [ $wlan2 -ne 1 ]; then

			sudo echo -e Interface wlan2 no detectada'\n' >> $log_file
			sudo echo -e Se procede a racargar wlan2'\n' >> $log_file
			RELOAD_INTERFACE wlan2
		fi
		action=1
	fi

	ip_wlan0=$(sudo ifconfig wlan0 | grep -w "inet addr" | cut -d ":" -f2 | cut -d " " -f1)
	if [ "$ip_wlan0" != "192.168.42.1" ]; then

		sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' WLAN0 no esta correctamente configurada'\n' >> $log_file
		sudo ifconfig wlan0 >> $log_file
		sudo echo -e '\n'Se procede a re-cargar parametros a red wifi UB >> $log_file
		sudo ifconfig wlan0 192.168.42.1 netmask 255.255.255.0 broadcast 192.168.42.255

		action=1
	fi


	if [ "$WLAN0_WPA_CLI_CHECK_ENABLE" == "1" ]; then

		WLAN1_N_CONNECT_ATTEMPTS=`head -6 $line $stats_file | tail -1`
		
		# check wlan1 reconnection to wlan0 with wpa_cli status
		wlan1_wpa_cli_status=$(wpa_cli -i wlan1 status | grep "wpa_state" | cut -d"=" -f2)
		sudo echo -e $(date +"%d-%m-%Y %H:%M:%S") >> $WLAN0_STATS_FILE
		sudo echo -e Status:'\t'$wlan1_wpa_cli_status'\t'Quality:'\t'$(sudo iwconfig wlan1 | grep -i "Quality")'\n' >> $WLAN0_STATS_FILE

		if [[ "$wlan1_wpa_cli_status" == "COMPLETED" ]]; then
			
			WLAN1_N_CONNECT_ATTEMPTS=0
			sudo sed -i "6s/.*/$WLAN1_N_CONNECT_ATTEMPTS/" $stats_file

		else

			sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t'wlan1 cannot connect to Wifi1/wlan0'\n' >> $log_file

			WLAN1_N_CONNECT_ATTEMPTS=$((WLAN1_N_CONNECT_ATTEMPTS + 1))
			sudo sed -i "6s/.*/$WLAN1_N_CONNECT_ATTEMPTS/" $stats_file
			echo -e Cummulative wlan1 connection attempts $WLAN1_N_CONNECT_ATTEMPTS >> $log_file


			wlan0_wlan1_reset_handle_1=$(expr $WLAN1_N_CONNECT_ATTEMPTS % $WLAN1_N_CONNECT_MAX_1)            #   Hard reset USB adapter
			wlan0_wlan1_reset_handle_2=$(expr $WLAN1_N_CONNECT_ATTEMPTS % $WLAN1_N_CONNECT_MAX_2)            #   Hard reset Raspberry Pi HUB and PCB HUB  
			wlan0_wlan1_reset_handle_3=$(expr $WLAN1_N_CONNECT_ATTEMPTS % $WLAN1_N_CONNECT_MAX_3)            #   Hard reset Raspberry Pi

			if [ $wlan0_wlan1_reset_handle_3 -eq 0 ]; then

				sudo echo "Maximum wlan1 handle 3 connection attempts reached ($WLAN1_N_CONNECT_MAX_3). Proceeding to reset Raspberry Pi" >> $log_file
				RESET_RPI
				exit 0
			fi
			if [ $wlan0_wlan1_reset_handle_2 -eq 0 ]; then

				sudo echo "Maximum wlan1 handle 2 connection attempts reached ($WLAN1_N_CONNECT_MAX_2). Proceeding to hard reset PCB HUB" >> $log_file
				RELOAD_PCB_HUB
				exit 0
			fi

			if [ $wlan0_wlan1_reset_handle_1 -eq 0 ]; then

				sudo echo "Maximum wlan1 handle 1 connection attempts reached ($WLAN1_N_CONNECT_MAX_1). Proceeding to hard reset Wifi/wlan0 USB adapter" >> $log_file
				
				RELOAD_MODULO_WIFI1_WLAN0
				RELOAD_WIFI_WIFI1_WLAN0_SW
			fi
		fi
		sudo wpa_cli -i wlan1 reconnect
		sudo wpa_cli -i wlan1 reconfigure
	fi
fi



if [ "$GSM_ENABLE" == "1" ]; then

	n_no_lsusb=`head -3 $line $stats_file | tail -1`
	n_no_conexion=`head -4 $line $stats_file | tail -1`
	n_no_conectividad=`head -5 $line $stats_file | tail -1`

	gsm_modem=$(sudo echo "$usb_list" | grep "$GSM_MODEM" | wc -l)
	if [ $gsm_modem -ne 1 ]; then

		sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' BAM no detectada en lsusb'\n'  >> $log_file
		sudo echo -e "$usb_list"'\n' >> $log_file

		n_no_lsusb=$((n_no_lsusb + 1))
		sudo sed -i "3s/.*/$n_no_lsusb/" $stats_file

		reinicio=$(expr $n_no_lsusb % $reinicio_cada_x_no_detecciones)
		if [ $reinicio -eq 0 ]; then

			echo -e Alcanzadas "$n_no_lsusb" no detecciones de BAM en lsusb consecutivas  >> $log_file
			sudo echo -e Se ejecutara un reinicio de RPI >> $log_file
			sudo echo -e ------------------------------------------------------------------------------------------------------------ >> $log_file
			RESET_RPI
		else

			sudo echo -e Cantidad de no detecciones en lsusb consecutivas: "$n_no_lsusb" >> $log_file
			sudo echo -e Se intenta re-deteccion de BAM >> $log_file
			RELOAD_GSM_MODEM
		fi

		action=1

	else
		if [ $n_no_lsusb -ne "0" ]; then
			n_no_lsusb=0
			sudo sed -i "3s/.*/$n_no_lsusb/" $stats_file
		fi

		if [ "$GSM_MODEM" == "Huawei Technologies" ]; then

			ppp0=`/sbin/ifconfig ppp0 | grep inet\ addr | wc -l`
			if [ $ppp0 -eq 0 ]; then

				sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' BAM detectada en lsusb, pero interfaz ppp0 inactiva, se reintenta conexion  >> $log_file
				respuesta="$(sudo /opt/sakis3g/sakis3g --sudo "connect")"
				sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Reporte de la BAM:'\n\n'"$respuesta"'\n' >> $log_file


				if [[ "$respuesta" == *"$r1"* ]]; then

					if [ $n_no_conexion -ne "0" ]; then
						n_no_conexion=0
						sudo sed -i "4s/.*/$n_no_conexion/" $stats_file
					fi

					if [ $n_no_conectividad -ne "0" ]; then
						n_no_conectividad=0
						sudo sed -i "5s/.*/$n_no_conectividad/" $stats_file
					fi

					SEND_ID "ppp0"

				else

					n_no_conexion=$((n_no_conexion + 1))
					sudo sed -i "4s/.*/$n_no_conexion/" $stats_file

					sudo echo -e Intento de conexion fallido N� "$n_no_conexion" >> $log_file

					reinicio=$(expr $n_no_conexion % $reinicio_cada_x_no_conexiones)
					if [ $reinicio -eq 0 ]; then

						sudo echo -e Alcanzados "$n_no_conexion" intentos de conexion fallidos consecutivos  >> $log_file
						sudo echo -e Se ejecutara un reinicio de RPI >> $log_file
						sudo echo -e ------------------------------------------------------------------------------------------------------------ >> $log_file
						RESET_RPI
					else

						if [[ "$respuesta" == *"$r2"* ]]; then

							sudo echo -e Se espera por siguiente intento de conexion >> $log_file

						elif [[ "$respuesta" == *"$r3"* ]]; then

							sudo echo -e Se intenta re-deteccion de BAM por no detectarse capacidades GSM en BAM >> $log_file
							RELOAD_BAM_HUB

						elif [[ "$respuesta" == *"$r4"* ]]; then

							sudo echo -e Se intenta re-deteccion de BAM por no registrarse en red ISP >> $log_file
							RELOAD_BAM_HUB
						else
							sudo echo -e Respuesta de BAM desconocida, se espera por siguiente intento de conexion  >> $log_file
						fi
					fi
				fi

				action=1

			else

				ping=$(sudo timeout 15 ping google.cl -c 2 | grep '2 received' | wc -l)
				if [ $ping -eq 0 ]; then

					n_no_conectividad=$((n_no_conectividad + 1))
					sudo sed -i "5s/.*/$n_no_conectividad/" $stats_file

					sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Interfaz ppp0 activa pero sin conectividad en: "$n_no_conectividad" intentos >> $log_file

					desconexion=$(expr $n_no_conectividad % $desconexion_cada_x_sin_conectividad)
					if [ $desconexion -eq 0 ]; then

						sudo echo -e Se inicia desconexion de BAM  >> $log_file
						respuesta="$(sudo /opt/sakis3g/sakis3g "--sudo" "disconnect")"
						sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Reporte de la BAM:'\n\n'"$respuesta" >> $log_file
					fi

					action=1

				else

					if [ $n_no_conectividad -ne "0" ]; then
						n_no_conectividad=0
						sudo sed -i "5s/.*/$n_no_conectividad/" $stats_file

						sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Conectividad, restaurada  >> $log_file

						action=1
					fi

					send_id_time=$(expr $(date +"%M") % $id_cada_x_min)
					if [ $send_id_time -eq 0 ]; then

						SEND_ID "ppp0"
					fi
				fi
			fi
			
		else
		
			eth1=`/sbin/ifconfig eth1 | grep inet\ addr | wc -l`
			if [ $eth1 -eq 0 ]; then

				sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' BAM detectada en lsusb, pero interfaz eth1 inactiva, se reintenta re-conexion de BAM  >> $log_file
				
				RELOAD_GSM_MODEM
			
			else
				ping=$(sudo timeout 15 ping google.cl -c 2 | grep '2 received' | wc -l)
				if [ $ping -eq 0 ]; then

					n_no_conectividad=$((n_no_conectividad + 1))
					sudo sed -i "5s/.*/$n_no_conectividad/" $stats_file

					sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Interfaz eth1 activa pero sin conectividad en: "$n_no_conectividad" intentos >> $log_file

					desconexion=$(expr $n_no_conectividad % $desconexion_cada_x_sin_conectividad)
					if [ $desconexion -eq 0 ]; then

						sudo echo -e Se inicia re-conexion de BAM de BAM  >> $log_file
						
						RELOAD_GSM_MODEM
					
					fi

					action=1

				else

					if [ $n_no_conectividad -ne "0" ]; then
						n_no_conectividad=0
						sudo sed -i "5s/.*/$n_no_conectividad/" $stats_file

						sudo echo -e $(date +"%d-%m-%Y %H:%M:%S")'\t' Conectividad, restaurada  >> $log_file

						action=1

					fi

					send_id_time=$(expr $(date +"%M") % $id_cada_x_min)
					if [ $send_id_time -eq 0 ]; then 

						SEND_ID "eth1"
					fi
				fi
			
			fi	
		
		fi
	fi
else
	if [ "$GSM_DISABLE_INTERNET_ACCESS" == "1" ]; then

		send_id_time=$(expr $(date +"%M") % $id_cada_x_min)
		if [ $send_id_time -eq 0 ]; then

			SEND_ID "eth0"
		fi
	fi
fi


if [ $action -eq "1" ]; then
	sudo echo -e ------------------------------------------------------------------------------------------------------------ >> $log_file
fi

script_lock=0
sudo sed -i "1s/.*/$script_lock/" $stats_file
