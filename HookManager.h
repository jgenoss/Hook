#pragma once
//#include "pch.h"
#include <map>
#include <string>
#include <fstream>
#include <iostream>

class HookManager {
private:
    // Estructura para almacenar informaci�n de los hooks
    struct HookInfo {
        std::string dllName;
        std::string funcName;
        std::string decoratedName;
        void* originalFunc;
        void* hookFunc;
        bool isHooked;
    };

    // Mapa para registrar todos los hooks por un ID �nico
    std::map<std::string, HookInfo> hooks;

    // Archivo de log
    std::ofstream logFile;

    // Singleton
    static HookManager* instance;

    // Constructor privado (patr�n singleton)
    HookManager();

public:
    // Obtener instancia
    static HookManager* GetInstance();

    // Destructor
    ~HookManager();

    // Funci�n para registrar en el log
    void Log(const std::string& message);

    // Funci�n para registrar un nuevo hook
    bool RegisterHook(const std::string& hookId, const std::string& dllName,
        const std::string& funcName, const std::string& decoratedName,
        void* hookFunction);

    // Funci�n para instalar un hook espec�fico
    bool InstallHook(const std::string& hookId);

    // Funci�n para desinstalar un hook espec�fico
    bool UninstallHook(const std::string& hookId);

    // Funci�n para obtener la funci�n original
    template<typename T>
    T GetOriginalFunction(const std::string& hookId) {
        auto it = hooks.find(hookId);
        if (it == hooks.end() || !it->second.originalFunc) {
            return nullptr;
        }

        return (T)(it->second.originalFunc);
    }

    // Instalar todos los hooks registrados
    void InstallAllHooks();

    // Desinstalar todos los hooks
    void UnhookAll();
};