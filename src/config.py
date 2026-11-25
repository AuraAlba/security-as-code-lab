import os

"""Configuración de la aplicación: las credenciales se obtienen desde el entorno."""

APP_API_TOKEN = os.getenv("APP_API_TOKEN", "")