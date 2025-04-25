#pragma once
#include <map>
#include <string>
#include <fstream>
#include <iostream>
#include <vector>

// Clase para gestionar los hooks internos
class InternalHookManager {
private:
    // Estructura para almacenar informaci�n de los hooks internos
    struct InternalHookInfo {
        std::string moduleName;       // Nombre del m�dulo donde se encuentra la funci�n (puede ser vac�o)
        std::string funcName;         // Nombre descriptivo de la funci�n
        std::string patternOrAddress; // Patr�n o direcci�n para encontrar la funci�n
        void* originalFunc;           // Puntero a la funci�n original
        void* hookFunc;               // Puntero a la funci�n hook
        bool isHooked;                // Estado del hook
    };

    // Mapa para registrar todos los hooks internos por un ID �nico
    std::map<std::string, InternalHookInfo> internalHooks;

    // Archivo de log
    std::ofstream logFile;

    // Referencia al singleton HookManager para logging
    void* hookManager;

    // Puntero a la funci�n de logging en HookManager
    typedef void (*LogFunction)(void* manager, const std::string& message);
    LogFunction logFunc;

    // Singleton
    static InternalHookManager* instance;

    // Constructor privado (patr�n singleton)
    InternalHookManager();

    // Log interno si no hay HookManager disponible
    void InternalLog(const std::string& message);

public:
    // Obtener instancia
    static InternalHookManager* GetInstance();

    // Destructor
    ~InternalHookManager();

    // Configurar el HookManager para usar su funci�n de log
    void SetHookManager(void* manager, LogFunction logFn);

    // Funci�n para registrar en el log
    void Log(const std::string& message);

    // Funci�n utilitaria para encontrar patrones de bytes en memoria
    void* FindPattern(const char* pattern, const char* mask, void* start, size_t size);

    // Funci�n para buscar una funci�n por su patr�n de bytes
    void* FindFunctionByPattern(const char* pattern, const char* mask, const char* moduleName = nullptr);

    // Funci�n para convertir un string hexadecimal a un patr�n de bytes
    bool HexStringToPattern(const std::string& hexStr, std::vector<char>& pattern, std::string& mask);

    // Funci�n para encontrar una funci�n por un patr�n en formato de string hexadecimal
    void* FindFunctionByHexPattern(const std::string& hexPattern, const char* moduleName = nullptr);

    // Funci�n para procesar patrones en diversos formatos
    void* ProcessPatternOrAddress(const std::string& patternOrAddress, const char* moduleName = nullptr);

    // Funci�n para registrar un hook interno con direcci�n conocida
    bool RegisterHook(const std::string& hookId, void* targetAddress,
        const std::string& funcName, void* hookFunction);

    // Funci�n para registrar un hook interno usando patr�n o direcci�n en forma de string
    bool RegisterHook(const std::string& hookId, const std::string& moduleName,
        const std::string& funcName, const std::string& patternOrAddress,
        void* hookFunction);

    // Funci�n para instalar un hook interno espec�fico
    bool InstallHook(const std::string& hookId);

    // Funci�n para desinstalar un hook espec�fico
    bool UninstallHook(const std::string& hookId);

    // Funci�n para obtener la funci�n original
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