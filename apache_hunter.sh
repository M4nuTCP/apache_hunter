#!/bin/bash

# COLORES
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

function ctrl_c(){
    echo -e "\n\n${redColour}[!] Saliendo...${endColour}\n"
    exit 1 
}

trap ctrl_c INT

LOG_FILE="/var/log/apache2/access.log"

mostrar_ayuda() {
    echo
    echo -e "${yellowColour}  -i${endColour}    Fecha y hora de inicio (formato: DD-MM-YYYY HH:MM:SS)"
    echo -e "${yellowColour}  -f${endColour}    Fecha y hora de fin (formato: DD-MM-YYYY HH:MM:SS)"
    echo -e "${yellowColour}  -o${endColour}    Archivo de salida donde se guardarán los registros extraídos (opcional)"
    echo -e "${yellowColour}  -p${endColour}    Filtrar por dirección IP"
    echo -e "${yellowColour}  -c${endColour}    Filtrar por código de estado HTTP (opcional)"
    echo -e "${yellowColour}  -r${endColour}    Mostrar un resumen de accesos por IP y códigos HTTP"
    echo -e "${yellowColour}  -z${endColour}    Comprimir el archivo de salida en formato .zip"
    echo -e "${yellowColour}  -h${endColour}    Muestra esta ayuda"
    echo
    echo -e "${purpleColour}Ejemplo: $0 ${yellowColour}-i${purpleColour} \"28-10-2024 14:30:00\" ${yellowColour}-f${purpleColour} \"30-10-2024 10:45:00\" ${yellowColour}-o${purpleColour} salida.txt ${yellowColour}-p${purpleColour} \"192.168.1.1\"${endColour}"
}

convertir_a_timestamp() {
    date -d "$(echo $1 | sed 's/\([0-9]\{2\}\)-\([0-9]\{2\}\)-\([0-9]\{4\}\)/\3-\2-\1/')" +"%s"
}

while getopts "i:f:o:hp:c:rz" opt; do
    case $opt in
        i) FECHA_INICIO="$OPTARG" ;;
        f) FECHA_FIN="$OPTARG" ;;
        o) ARCHIVO_SALIDA="$OPTARG" ;;
        p) IP_FILTRO="$OPTARG" ;;
        c) CODIGO_HTTP="$OPTARG" ;;
        r) RESUMEN=1 ;;
        z) COMPRIMIR=1 ;;
        h) mostrar_ayuda
           exit 0
           ;;
        *) mostrar_ayuda
           exit 1
           ;;
    esac
done

if [[ "$RESUMEN" -eq 1 ]]; then
    echo -e "\n${greenColour}[+] Resumen de accesos por IP:${endColour}\n"
    awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr

    echo -e "\n${greenColour}[+] Resumen de códigos HTTP:${endColour}\n"
    awk '{print $9}' "$LOG_FILE" | grep -E '^[0-9]{3}$' | sort | uniq -c | sort -nr

    exit 0
fi

if [[ -z "$FECHA_INICIO" || -z "$FECHA_FIN" ]] && [[ -z "$IP_FILTRO" ]]; then
    echo -e "\n${redColour}[!] Error: faltan argumentos obligatorios.${endColour}"
    mostrar_ayuda
    exit 1
fi

if [[ -n "$IP_FILTRO" && -z "$FECHA_INICIO" && -z "$FECHA_FIN" ]]; then
    TEMP_FILE=$(mktemp)
    grep "^$IP_FILTRO" "$LOG_FILE" > "$TEMP_FILE"

    LINE_COUNT=$(wc -l < "$TEMP_FILE")
    echo -e "${greenColour}[+]${endColour} El resultado tiene ${yellowColour}$LINE_COUNT${endColour} líneas.\n"

    if [[ $LINE_COUNT -gt 50 ]]; then
        echo -e "${yellowColour}[?]${endColour} ¿Deseas reportar por consola (c) o abrir con nano (n)? (c/n):"
        read -r choice
        if [[ "$choice" == "n" ]]; then
            nano "$TEMP_FILE"
        else
            cat "$TEMP_FILE"
        fi
    else
        cat "$TEMP_FILE"
    fi

    rm -f "$TEMP_FILE"
    exit 0
fi

TIMESTAMP_INICIO=$(convertir_a_timestamp "$FECHA_INICIO")
TIMESTAMP_FIN=$(convertir_a_timestamp "$FECHA_FIN")

if [[ $TIMESTAMP_INICIO -ge $TIMESTAMP_FIN ]]; then
    echo -e "\n${redColour}[!] Error: la fecha de inicio debe ser anterior a la fecha de fin.${endColour}"
    exit 1
fi

TEMP_FILE=$(mktemp)

awk -v inicio="$TIMESTAMP_INICIO" -v fin="$TIMESTAMP_FIN" -v ip_filtro="$IP_FILTRO" -v codigo_http="$CODIGO_HTTP" '
    {
        match($0, /\[([0-9]{2})\/([A-Za-z]{3})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+\-][0-9]{4})\]/, fecha);
        if (fecha[0] != "") {
            meses["Jan"]=1; meses["Feb"]=2; meses["Mar"]=3; meses["Apr"]=4;
            meses["May"]=5; meses["Jun"]=6; meses["Jul"]=7; meses["Aug"]=8;
            meses["Sep"]=9; meses["Oct"]=10; meses["Nov"]=11; meses["Dec"]=12;
            timestamp_log = mktime(fecha[3] " " meses[fecha[2]] " " fecha[1] " " fecha[4] " " fecha[5] " " fecha[6]);
            if (timestamp_log >= inicio && timestamp_log <= fin && (ip_filtro == "" || $1 == ip_filtro) && (codigo_http == "" || $9 == codigo_http)) {
                print $0;
            }
        }
    }
' "$LOG_FILE" > "$TEMP_FILE"

LINE_COUNT=$(wc -l < "$TEMP_FILE")

if [[ -z "$ARCHIVO_SALIDA" ]]; then
    echo -e "${greenColour}[+]${endColour} El resultado tiene ${yellowColour}$LINE_COUNT${endColour} líneas."
    if [[ $LINE_COUNT -gt 50 ]]; then
        echo -e "${yellowColour}[?]${endColour} ¿Deseas reportar por consola (c) o abrir con nano (n)? (c/n):"
        read -r choice
        if [[ "$choice" == "n" ]]; then
            nano "$TEMP_FILE"
        else
            cat "$TEMP_FILE"
        fi
    else
        cat "$TEMP_FILE"
    fi
else
    mv "$TEMP_FILE" "$ARCHIVO_SALIDA"
    echo -e "\n${greenColour}[+] ${endColour}Registros extraídos correctamente al archivo:${yellowColour} $ARCHIVO_SALIDA${endColour}"

    if [[ "$COMPRIMIR" -eq 1 ]]; then
        zip "${ARCHIVO_SALIDA}.zip" "$ARCHIVO_SALIDA" &> /dev/null
        if [[ $? -eq 0 ]]; then
            echo -e "\n${greenColour}[+]${endColour} Archivo comprimido como:${yellowColour} ${ARCHIVO_SALIDA}.zip${endColour}"
            rm "$ARCHIVO_SALIDA"
        else
            echo -e "\n${redColour}[!]${endColour} Error al comprimir el archivo."
        fi
    fi
fi

rm -f "$TEMP_FILE"
