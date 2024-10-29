# apache_hunter


**Apache Hunter** es un conjunto de herramientas diseñadas para monitorizar y analizar los logs de un servidor Apache. Proporciona dos scripts principales:

- **Herramienta 1: apache_hunter.sh**: Un script de línea de comandos para extraer, filtrar y analizar los registros de acceso de Apache, con opciones para buscar por rangos de fechas, direcciones IP, códigos HTTP y más.
- **Herramienta 2: apache_hunter_daemon.sh**: Un script de monitorización en tiempo real que detecta patrones de actividad maliciosa en los logs, genera reportes detallados y ofrece una visualización interactiva mediante un sitio HTML.

<p align="center">
  <img src="https://github.com/user-attachments/assets/8ce0c1ed-f7dc-4f4e-94ae-1472f2089d30" alt="image" width="300">
</p>
  
## apache_hunter.sh

apache_hunter.sh sirve para analizar registros de acceso de Apache, permitiendo filtrar y extraer información según rangos de fechas, direcciones IP, y códigos de estado HTTP. Además, ofrece un resumen de accesos por IP y códigos, y la posibilidad de guardar o comprimir los resultados. Es útil para monitorear y auditar la actividad en un servidor web.

  ### Opciones

  ```bash
  -i    Fecha y hora de inicio (formato: DD-MM-YYYY HH:MM:SS)
  -f    Fecha y hora de fin (formato: DD-MM-YYYY HH:MM:SS)
  -o    Archivo de salida donde se guardarán los registros extraídos (opcional)
  -p    Filtrar por dirección IP
  -c    Filtrar por código de estado HTTP (opcional)
  -r    Mostrar un resumen de accesos por IP y códigos HTTP
  -z    Comprimir el archivo de salida en formato .zip
  -h    Muestra esta ayuda

Ejemplo: ./apache_hunter.sh -i "28-10-2024 14:30:00" -f "30-10-2024 10:45:00" -o salida.txt -p "192.168.1.1"
  ```

## apache_hunter_daemon.sh

apache_hunter_daemon.sh es una herramienta escrita en Bash que organiza y reporta los registros de acceso de Apache, detectando y clasificando las IPs maliciosas encontradas en el archivo access.log. La detección se basa en patrones como rutas sospechosas, tiempo entre peticiones (para identificar ataques de fuerza bruta), el User-Agent, entre otros criterios.

Lo que hace esta herramienta es recopilar estos registros y almacenarlos en directorios bien organizados, facilitando la gestión de los datos. Además, genera una interfaz web visual que permite filtrar y analizar de manera más eficiente los registros maliciosos que llegan a tu página web, ofreciendo una forma intuitiva de monitorear las amenazas.

![image](https://github.com/user-attachments/assets/5539efa6-7f21-4237-869b-fd58e5a0d4d7)

![image](https://github.com/user-attachments/assets/c80775b7-063e-465e-8ee4-8ca2212fae60)

## Instalaciones

1. **Ubicación de instalación**:
   Apache Hunter debe instalarse en `/var/log/apache2/`. Para hacerlo, sigue estos pasos:

   ```bash
   cd /var/log/apache2/
   git clone https://github.com/tu-usuario/apache_hunter.git
    ```
Es recomendable crear un servicio de `apache_hunter_daemon.sh` para que este corriendo en el servidor todo el tiempo

  ### Creación de un servicio

  1. Crea un archivo de servicio en el directorio `/etc/systemd/system/` llamado `apache_hunter.service`:

   ```bash
     sudo nano /etc/systemd/system/apache_hunter.service
   ```
   2. Configurar el archivo de servicio: Agrega el siguiente contenido al archivo apache_hunter.service:

   ```bash
    [Unit]
    Description=Servicio para monitorización de logs de Apache con Apache Hunter
    After=network.target
  
    [Service]
    ExecStart=/var/log/apache2/apache_hunter/apache_hunter_daemon.sh
    Restart=always
    User=root
  
    [Install]
    WantedBy=multi-user.target
   ```
  3. Habilitar y arrancar el servicio: Ejecuta los siguientes comandos para recargar la configuración de systemd y activar el servicio:

   ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable apache_hunter.service
    sudo systemctl start apache_hunter.service
   ```
  
