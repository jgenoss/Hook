#pragma once
#include <map>
#include <string>
#include <fstream>
#include <iostream>
#include <vector>

// Clase para gestionar los hooks internos
class InternalHookManager {
private:
    // Estructura para almacenar información de los hooks internos
    struct InternalHookInfo {
        std::string moduleName;       // Nombre del módulo donde se encuentra la función (puede ser vacío)
        std::string funcName;         // Nombre descriptivo de la función
        std::string patternOrAddress; // Patrón o dirección para encontrar la función
        void* originalFunc;           // Puntero a la función original
        void* hookFunc;               // Puntero a la función hook
        bool isHooked;                // Estado del hook
    };

    // Mapa para registrar todos los hooks internos por un ID único
    std::map<std::string, InternalHookInfo> internalHooks;

    // Archivo de log
    std::ofstream logFile;

    // Referencia al singleton HookManager para logging
    void* hookManager;

    // Puntero a la función de logging en HookManager
    typedef void (*LogFunction)(void* manager, const std::string& message);
    LogFunction logFunc;

    // Singleton
    static InternalHookManager* instance;

    // Constructor privado (patrón singleton)
    InternalHookManager();

    // Log interno si no hay HookManager disponible
    void InternalLog(const std::string& message);

public:
    // Obtener instancia
    static InternalHookManager* GetInstance();

    // Destructor
    ~InternalHookManager();

    // Configurar el HookManager para usar su función de log
    void SetHookManager(void* manager, LogFunction logFn);

    // Función para registrar en el log
    void Log(const std::string& message);

    // Función utilitaria para encontrar patrones de bytes en memoria
    void* FindPattern(const char* pattern, const char* mask, void* start, size_t size);

    // Función para buscar una función por su patrón de bytes
    void* FindFunctionByPattern(const char* pattern, const char* mask, const char* moduleName = nullptr);

    // Función para convertir un string hexadecimal a un patrón de bytes
    bool HexStringToPattern(const std::string& hexStr, std::vector<char>& pattern, std::string& mask);

    // Función para encontrar una función por un patrón en formato de string hexadecimal
    void* FindFunctionByHexPattern(const std::string& hexPattern, const char* moduleName = nullptr);

    // Función para procesar patrones en diversos formatos
    void* ProcessPatternOrAddress(const std::string& patternOrAddress, const char* moduleName = nullptr);

    // Función para registrar un hook interno con dirección conocida
    bool RegisterHook(const std::string& hookId, void* targetAddress,
        const std::string& funcName, void* hookFunction);

    // Función para registrar un hook interno usando patrón o dirección en forma de string
    bool RegisterHook(const std::string& hookId, const std::string& moduleName,
        const std::string& funcName, const std::string& patternOrAddress,
        void* hookFunction);

    // Función para instalar un hook interno específico
    bool InstallHook(const std::string& hookId);

    // Función para desinstalar un hook específico
    bool UninstallHook(const std::string& hookId);

    // Función para obtener la función original
    template<typename T>
    T GetOriginalFunction(const std::string& hookId) {
        auto it = internalHooks.find(hookId);
        if (it == internalHooks.end() || !it->second.originalFunc) {
            return nullptr;
        }

        return (T)(it->second.originalFunc);
    }

    // Instalar todos los hooks registrados
    void InstallAllHooks();

    // Desinstalar todos los hooks
    void UnhookAll();
};