#!/bin/bash

LOG_FILE="/var/log/apache2/access.log"
BASE_DIR="/var/log/apache2/apache_hunter"
SITE_DIR="${BASE_DIR}/site"
WHITELIST_ALL_FILE="${BASE_DIR}/whitelist_all.txt"

mkdir -p "$SITE_DIR"
mkdir -p "${BASE_DIR}/reports"
touch "$WHITELIST_ALL_FILE"

REPORT_JSON="${SITE_DIR}/report.json"
EVIL_LOGS_JSON="${SITE_DIR}/evil_logs.json"
WHITELIST_JSON="${SITE_DIR}/whitelist.json"

if [[ ! -f "$REPORT_JSON" ]]; then
    echo '[]' > "$REPORT_JSON"
fi

if [[ ! -f "$EVIL_LOGS_JSON" ]]; then
    echo '[]' > "$EVIL_LOGS_JSON"
fi

if [[ ! -f "$WHITELIST_JSON" ]]; then
    echo '[]' > "$WHITELIST_JSON"
fi

declare -A ATTACK_PATTERNS=(
    ["gobuster"]="gobuster"
    ["sqlmap"]="sqlmap"
    ["nikto"]="nikto"
    ["dirb"]="dirb"
    ["fuzz"]="ffuf"
    ["wpscan"]="wpscan"
    ["nmap"]="nmap"
    ["whatweb"]="whatweb"
    ["metasploit"]="metasploit"
    ["nessus"]="nessus"
    ["acunetix"]="acunetix"
    ["sqlninja"]="sqlninja"
    ["paros"]="paros"
    ["burp"]="burp"
    ["zaproxy"]="zaproxy"
    ["curl"]="curl"
    ["httprobe"]="httprobe"
    ["rat"]="rat"
    ["hydra"]="hydra"
    ["brutus"]="brutus"
    ["masscan"]="masscan"
    ["jaeles"]="jaeles"
    ["sql_injection"]="'|\"|--|;|OR 1=1|UNION SELECT|DROP TABLE|INSERT INTO|UPDATE|DELETE FROM"
    ["path_traversal"]="\.\./|\%2e\%2e\%2f|\%2e\%2e|\%252e\%252e\%252f"
)

check_sensitive_files() {
    local line="$1"
    if echo "$line" | grep -E "/etc/passwd|/config\.php|/wp-config\.php|/admin|/phpmyadmin" &> /dev/null; then
        echo "$line" >> "$EVIL_LOGS_FILE"
        jq --arg date "$(date)" --arg ip "$ip" --arg log "$line" '. += [{"date": $date, "ip": $ip, "log": $log}]' "$EVIL_LOGS_JSON" > "${EVIL_LOGS_JSON}.tmp" && mv "${EVIL_LOGS_JSON}.tmp" "$EVIL_LOGS_JSON"
    fi
}

check_activity_patterns() {
    local line="$1"
    local ip=$(echo "$line" | awk '{print $1}')
    local user_agent=$(echo "$line" | sed -n 's/.*\"\(.*\)\"$/\1/p')
    local request=$(echo "$line" | awk '{print $7}')
    local status_code=$(echo "$line" | awk '{print $9}')

    if [[ -n "$status_code" && "$status_code" =~ ^[0-9]+$ && ( "$status_code" -eq 404 || "$status_code" -eq 403 || "$status_code" -eq 401 ) ]]; then
    echo "$line" >> "$EVIL_LOGS_FILE"
    jq --arg date "$(date)" --arg ip "$ip" --arg log "$line" '. += [{"date": $date, "ip": $ip, "log": $log}]' "$EVIL_LOGS_JSON" > "${EVIL_LOGS_JSON}.tmp" && mv "${EVIL_LOGS_JSON}.tmp" "$EVIL_LOGS_JSON"
    fi

    ip_request_count=$(grep "$ip" "$LOG_FILE" | wc -l)
    if [[ -n "$ip_request_count" && "$ip_request_count" =~ ^[0-9]+$ && "$ip_request_count" -gt 100 ]]; then
        echo "$line" >> "$EVIL_LOGS_FILE"
        jq --arg date "$(date)" --arg ip "$ip" --arg log "$line" '. += [{"date": $date, "ip": $ip, "log": $log}]' "$EVIL_LOGS_JSON" > "${EVIL_LOGS_JSON}.tmp" && mv "${EVIL_LOGS_JSON}.tmp" "$EVIL_LOGS_JSON"
    fi

}

monitorizar_logs() {
    current_month_year=$(date +"%m-%Y")
    report_dir="${BASE_DIR}/reports/${current_month_year}_report"

    mkdir -p "$report_dir"

    REPORTE_FILE="${report_dir}/reporte.txt"
    WHITELIST_FILE="${report_dir}/whitelist.txt"
    EVIL_LOGS_FILE="${report_dir}/evil_logs.txt"

    declare -A IP_REGISTRADAS
    declare -A IP_USERAGENT_REGISTRADOS

    tail -F "$LOG_FILE" | while read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        user_agent=$(echo "$line" | sed -n 's/.*\"\(.*\)\"$/\1/p')

        for pattern in "${!ATTACK_PATTERNS[@]}"; do
            if echo "$line" | grep -iE "${ATTACK_PATTERNS[$pattern]}" &> /dev/null; then
                current_date=$(date +"%Y-%m-%d %H:%M:%S")
                key="$current_date|$ip|$user_agent"

                if [[ -z "${IP_USERAGENT_REGISTRADOS["$key"]}" ]]; then
                    echo "$(date) - IP: $ip - User-Agent: $user_agent" >> "$REPORTE_FILE"
                    IP_USERAGENT_REGISTRADOS["$key"]=1
                    jq --arg date "$current_date" --arg ip "$ip" --arg userAgent "$user_agent" \
                        '. += [{"date": $date, "ip": $ip, "userAgent": $userAgent}]' "$REPORT_JSON" > "${REPORT_JSON}.tmp" && mv "${REPORT_JSON}.tmp" "$REPORT_JSON"
                fi

                jq --arg date "$current_date" --arg ip "$ip" --arg log "$line" \
                    '. += [{"date": $date, "ip": $ip, "log": $log}]' "$EVIL_LOGS_JSON" > "${EVIL_LOGS_JSON}.tmp" && mv "${EVIL_LOGS_JSON}.tmp" "$EVIL_LOGS_JSON"
                echo "$line" >> "$EVIL_LOGS_FILE"

                if [[ -z "${IP_REGISTRADAS["$ip"]}" ]]; then
                    echo "$ip" >> "$WHITELIST_FILE"
                    IP_REGISTRADAS["$ip"]=1
                    if ! grep -q "^$ip$" "$WHITELIST_ALL_FILE"; then
                        echo "$ip" >> "$WHITELIST_ALL_FILE"
                        jq --arg ip "$ip" '. += [$ip]' "$WHITELIST_JSON" > "${WHITELIST_JSON}.tmp" && mv "${WHITELIST_JSON}.tmp" "$WHITELIST_JSON"
                    fi
                fi
                break
            fi
        done

        check_sensitive_files "$line"
        check_activity_patterns "$line"
    done
}

crear_html() {
    cat << 'EOF' > "${SITE_DIR}/index.html"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reporte de Logs Apache</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
        .container { width: 80%; margin: 0 auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        h1 { text-align: center; color: #333; }
        .filters { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .filters label { margin-right: 10px; }
        .filters select, .filters button { padding: 5px 10px; border: 1px solid #ccc; border-radius: 4px; }
        #reportChart { width: 100%; height: 400px; }
        #logDetails { margin-top: 20px; background: #fff; border: 1px solid #ccc; padding: 15px; border-radius: 8px; }
        #logDetails h2 { color: #333; }
        #logDetails pre { max-height: 300px; overflow-y: auto; background: #f4f4f4; padding: 10px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <h1>Reporte Visual de Logs Apache</h1>
        <div class="filters">
            <label for="year">Año:</label>
            <select id="year">
                <option value="all">Todos los años</option>
            </select>
            
            <label for="month">Mes:</label>
            <select id="month">
                <option value="all">Todos los meses</option>
                <option value="01">Enero</option>
                <option value="02">Febrero</option>
                <option value="03">Marzo</option>
                <option value="04">Abril</option>
                <option value="05">Mayo</option>
                <option value="06">Junio</option>
                <option value="07">Julio</option>
                <option value="08">Agosto</option>
                <option value="09">Septiembre</option>
                <option value="10">Octubre</option>
                <option value="11">Noviembre</option>
                <option value="12">Diciembre</option>
            </select>

            <label for="day">Día:</label>
            <select id="day">
                <option value="all">Todos los días</option>
            </select>
            
            <button id="filterButton">Filtrar</button>
        </div>

        <canvas id="reportChart"></canvas>

        <div id="logDetails" style="display: none;">
            <h2>Detalles de Logs Maliciosos</h2>
            <pre id="logContent"></pre>
        </div>
    </div>

    <script>
        const yearSelect = document.getElementById('year');
        const monthSelect = document.getElementById('month');
        const daySelect = document.getElementById('day');
        const filterButton = document.getElementById('filterButton');
        const currentYear = new Date().getFullYear();
        const logDetails = document.getElementById('logDetails');
        const logContent = document.getElementById('logContent');

        for (let i = currentYear; i >= 2024; i--) {
            let option = document.createElement('option');
            option.value = i;
            option.textContent = i;
            yearSelect.appendChild(option);
        }

        monthSelect.addEventListener('change', () => {
            fillDays();
        });

        yearSelect.addEventListener('change', () => {
            fillDays();
        });

        function fillDays() {
            if (monthSelect.value === "all") {
                daySelect.innerHTML = '<option value="all">Todos los días</option>';
            } else {
                const daysInMonth = new Date(yearSelect.value, monthSelect.value, 0).getDate();
                daySelect.innerHTML = '<option value="all">Todos los días</option>';
                for (let i = 1; i <= daysInMonth; i++) {
                    let option = document.createElement('option');
                    option.value = i < 10 ? `0${i}` : i;
                    option.textContent = i;
                    daySelect.appendChild(option);
                }
            }
        }

        let ctx = document.getElementById('reportChart').getContext('2d');
        let reportChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Logs maliciosos',
                    data: [],
                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                scales: {
                    x: { beginAtZero: true }
                },
                onClick: async (event, elements) => {
                    if (elements.length > 0) {
                        const index = elements[0].index;
                        const label = reportChart.data.labels[index];
                        const year = yearSelect.value;
                        const month = monthSelect.value;
                        const day = daySelect.value;

                        const response = await fetch('evil_logs.json');
                        if (!response.ok) {
                            console.error("Error al cargar los datos del JSON:", response.status);
                            return;
                        }

                        const evilLogs = await response.json();
                        let filteredLogs = [];

                        if (day === "all" && month === "all" && year === "all") {
                            filteredLogs = evilLogs.filter(log => log.date.startsWith(label));
                        } else if (day === "all" && month !== "all" && year !== "all") {
                            filteredLogs = evilLogs.filter(log => log.date.startsWith(`${year}-${month}-${label}`));
                        } else if (day !== "all" && month !== "all" && year !== "all") {
                            filteredLogs = evilLogs.filter(log => log.date.startsWith(`${year}-${month}-${day}`) && log.date.includes(label));
                        }

                        logContent.textContent = filteredLogs.map(log => log.log).join('\n');
                        logDetails.style.display = 'block';
                    }
                }
            }
        });

        filterButton.addEventListener('click', async () => {
            try {
                const year = yearSelect.value;
                const month = monthSelect.value;
                const day = daySelect.value;
                
                const response = await fetch('report.json');
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const reportData = await response.json();

                let labels = [];
                let data = [];
                let reportCount = {};

                if (year === "all" && month === "all" && day === "all") {
                    reportData.forEach(item => {
                        const [itemYear, itemMonth] = item.date.split(' ')[0].split('-');
                        const monthKey = `${itemYear}-${itemMonth}`;
                        if (!reportCount[monthKey]) {
                            reportCount[monthKey] = 0;
                        }
                        reportCount[monthKey]++;
                    });
                    labels = Object.keys(reportCount).sort();
                    data = Object.values(reportCount);
                } else if (month === "all" && year !== "all") {
                    reportData.forEach(item => {
                        const [itemYear, itemMonth] = item.date.split(' ')[0].split('-');
                        if (itemYear === year) {
                            if (!reportCount[itemMonth]) {
                                reportCount[itemMonth] = 0;
                            }
                            reportCount[itemMonth]++;
                        }
                    });
                    labels = Object.keys(reportCount).sort();
                    data = Object.values(reportCount);
                } else if (day === "all" && month !== "all") {
                    reportData.forEach(item => {
                        const [itemYear, itemMonth, itemDay] = item.date.split(' ')[0].split('-');
                        if (itemYear === year && itemMonth === month) {
                            if (!reportCount[itemDay]) {
                                reportCount[itemDay] = 0;
                            }
                            reportCount[itemDay]++;
                        }
                    });
                    for (let i = 1; i <= new Date(year, month, 0).getDate(); i++) {
                        const dayStr = i < 10 ? `0${i}` : `${i}`;
                        labels.push(dayStr);
                        data.push(reportCount[dayStr] || 0);
                    }
                } else {
                    reportData.forEach(item => {
                        const [itemYear, itemMonth, itemDay] = item.date.split(' ')[0].split('-');
                        const itemTime = item.date.split(' ')[1];
                        if (itemYear === year && itemMonth === month && itemDay === day) {
                            if (!reportCount[itemTime]) {
                                reportCount[itemTime] = 0;
                            }
                            reportCount[itemTime]++;
                        }
                    });
                    labels = Object.keys(reportCount).sort();
                    data = Object.values(reportCount);
                }

                reportChart.data.labels = labels;
                reportChart.data.datasets[0].data = data;
                reportChart.update();
            } catch (error) {
                console.error("Error al cargar los datos del JSON:", error);
            }
        });

        fillDays();
    </script>
</body>
</html>
EOF
}

crear_html
monitorizar_logs
