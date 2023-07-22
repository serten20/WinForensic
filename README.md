# WinForensic


El script obtiene la siguiente información:
1.	Eventos del visor de eventos (Sistema, Aplicación y Seguridad)
2.	Información de usuarios y cuentas:
    - Usuarios locales del sistema.
    - Perfiles de usuario y sesiones de inicio de sesión activas.
    - Grupos locales y los miembros del grupo "Administradores".
    - Creación, modificación y eliminación de usuarios
    - Inicios de sesión exitosos y fallidos
    - Eventos de enumeración de miembros de grupo local y de dominio.
3.	Información de red:
•	Conexiones TCP locales y remotas.
•	Rutas de red y adaptadores de red.
4.	Información del sistema:
•	Datos sobre el sistema, como el nombre de la máquina, dominio, etc.
•	Registra los parches (hotfixes) instalados en el sistema.
•	Obtiene el contenido del archivo "hosts".
•	lista de programas instalados en el sistema
5.	Búsqueda de actividades potencialmente sospechosas:
•	Verifica las claves de registro "Run" y "RunOnce" para detectar programas que se inician automáticamente y sean susceptibles de ganar persistencia en el sistema.
•	Busca archivos ejecutables y otros tipos sospechosos en las carpetas "AppData" y "Temp".
