# Reconocimiento inicial de Caido con REA

## Resultado

- Artefacto: Caido macOS 0.58.3, Electron.
- UI: bundle Vue compilado, cargado desde `packages/ui/dist/index.html`.
- El proceso principal es `dist/index.es.js`; el preload es `dist/preload.cjs.js`.
- La ventana de Electron carga `http://localhost:8081/`, así que la UI depende de un servicio local separado.
- REA reconstruyó módulos y límites Electron: 96 nodos y 115 relaciones en el análisis acotado.
- El preload expone llamadas IPC para abrir URLs y navegadores, iniciar/gestionar instancias locales y remotas, consultar versión e información del sistema, descargar logs y comprobar/descargar/instalar actualizaciones.
- Los bundles están minificados: REA marcó el análisis semántico como parcial. El reconocimiento sirve para establecer la arquitectura, no para inferir toda la lógica de producto.

## Integridad

El análisis del ASAR completo encontró una discrepancia entre el hash declarado y el binario nativo desempaquetado `registry.node`. El análisis acotado conserva evidencia de los bundles leídos, pero no usa ese binario como prueba de equivalencia. El análisis acotado está guardado como `rea-app-analysis.json`.

## Implicaciones para el clon

Una app de escritorio y otra Android necesitan compartir una capa de servicios de proxy y un protocolo de datos, con UIs separadas. La app Caido inspeccionada no es solo una interfaz web: arranca un backend local y usa IPC con Electron para funciones del sistema. La implementación actual en Python es únicamente un prototipo HTTP; todavía no tiene la arquitectura necesaria para paridad completa ni el cliente Android.
