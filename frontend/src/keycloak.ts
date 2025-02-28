// src/keycloak.js
import Keycloak from 'keycloak-js';

const keycloakConfig = {
  url: process.env.KEYCLOAK_URL, // URL вашего Keycloak сервера
  realm: process.env.KEYCLOAK_URL, // Название вашего realm
  clientId: process.env.KEYCLOAK_URL, // ID вашего клиента
};

const keycloak = new Keycloak(keycloakConfig);

export default keycloak;
