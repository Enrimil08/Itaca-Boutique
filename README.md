# itaca_boutique 

# 👗 Itaca Boutique - Full Stack Inventory System

**Itaca Boutique** es una aplicación web robusta diseñada para la gestión de productos y usuarios en el sector retail. Este proyecto demuestra una integración completa de un backend en **Python/Flask** con una base de datos relacional **MySQL**, permitiendo un control total sobre el inventario y la seguridad del acceso.

## 🚀 Características Técnicas

- **CRUD Completo de Productos:** Creación, lectura, actualización y eliminación de artículos con carga dinámica de imágenes.
- **Autenticación Segura:** Sistema de registro e inicio de sesión con hashing de contraseñas mediante `Werkzeug`.
- **Gestión de Sesiones:** Uso de sesiones de Flask con cookies de seguridad (HttpOnly, SameSite) y persistencia de 7 días.
- **Integración con MySQL:** Configuración dinámica capaz de detectar entornos locales o remotos (como JawsDB en Heroku).
- **Protección de Rutas:** Decoradores personalizados para restringir el acceso a funciones administrativas.
- **Validación de Formularios:** Implementación de `Flask-WTF` con validaciones de servidor para integridad de datos.

## 🛠️ Stack Tecnológico

- **Backend:** Python 3.x, Flask.
- **Base de Datos:** MySQL / MariaDB.
- **Frontend:** Jinja2 (Templates), HTML5, CSS3.
- **Seguridad:** Werkzeug (Security), Flask-WTF (CSRF Protection), Dotenv (Environment Variables).
- **Almacenamiento:** Sistema de archivos local para imágenes con nombres únicos (`uuid`).

## 📦 Instalación y Configuración

1. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/TU_USUARIO/itaca-boutique.git](https://github.com/TU_USUARIO/itaca-boutique.git)
   cd itaca-boutique

Desarrollado por [Enrique Miller] Full Stack Developer Junior | Especialista en Python & Flask

  
