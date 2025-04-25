#pragma once
#include "pch.h"
#include "HookManager.h"


// Inicialización del singleton
HookManager* HookManager::instance = nullptr;

HookManager::HookManager() {
    // Abrir archivo de log
    logFile.open("hooks_log.txt", std::ios::app);
    Log("HookManager inicializado");
}

HookManager* HookManager::GetInstance() {
    if (!instance) {
        instance = new HookManager();
    }
    return instance;
}

HookManager::~HookManager() {
    // Remover todos los hooks antes de destruir
    UnhookAll();

    if (logFile.is_open()) {
        logFile.close();
    }
}

void HookManager::Log(const std::string& message) {
    // Obtener tiempo actual
    SYSTEMTIME st;
    GetLocalTime(&st);

    // Formatear mensaje con timestamp
    char timestamp[64];
    sprintf_s(timestamp, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    // Escribir en archivo de log
    if (logFile.is_open()) {
        logFile << timestamp << message << std::endl;
        logFile.flush();
    }

    // Mostrar también en la consola
    std::cout << timestamp << message << std::endl;
}

bool HookManager::RegisterHook(const std::string& hookId, const std::string& dllName,
    const std::string& funcName, const std::string& decoratedName,
    void* hookFunction) {
    // Verificar si ya existe este hook
    if (hooks.find(hookId) != hooks.end()) {
        Log("Error: Hook ID ya existe: " + hookId);
        return false;
    }

    // Crear información del hook
    HookInfo info;
    info.dllName = dllName;
    info.funcName = funcName;
    info.decoratedName = decoratedName;
    info.originalFunc = nullptr;
    info.hookFunc = hookFunction;
    info.isHooked = false;

    // Registrar el hook
    hooks[hookId] = info;
    Log("Hook registrado: " + hookId + " para " + dllName + "::" + funcName);

    return true;
}

bool HookManager::InstallHook(const std::string& hookId) {
    // Verificar si existe el hook
    auto it = hooks.find(hookId);
    if (it == hooks.end()) {
        Log("Error: Hook ID no encontrado: " + hookId);
        return false;
    }

    HookInfo& info = it->second;

    // Si ya está hookeado, no hacer nada
    if (info.isHooked) {
        Log("Hook ya instalado: " + hookId);
        return true;
    }

    // Obtener handle de la DLL
    HMODULE hModule = GetModuleHandleA(info.dllName.c_str());
    if (!hModule) {
        Log("Error: No se encontró la DLL en memoria: " + info.dllName);
        return false;
    }

    // Intentar obtener la dirección de la función
    FARPROC procAddr = GetProcAddress(hModule, info.funcName.c_str());

    // Si no funciona con el nombre normal, intentar con el decorado (si está disponible)
    if (!procAddr && !info.decoratedName.empty()) {
        procAddr = GetProcAddress(hModule, info.decoratedName.c_str());
    }

    if (!procAddr) {
        Log("Error: No se encontró la función: " + info.funcName);
        return false;
    }

    // Guardar la función original
    info.originalFunc = reinterpret_cast<void*>(procAddr);

    Log("Funcion " + info.funcName + " encontrada en 0x" +
        std::to_string(reinterpret_cast<uintptr_t>(info.originalFunc)));

    // Instalar el hook
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG error = DetourAttach(&info.originalFunc, info.hookFunc);
    LONG commitError = DetourTransactionCommit();

    if (error != NO_ERROR || commitError != NO_ERROR) {
        Log("Error al instalar hook: " + std::to_string(error) + ", " + std::to_string(commitError));
        return false;
    }

    info.isHooked = true;
    Log("Hook instalado exitosamente: " + hookId);

    return true;
}

bool HookManager::UninstallHook(const std::string& hookId) {
    // Verificar si existe el hook
    auto it = hooks.find(hookId);
    if (it == hooks.end()) {
        Log("Error: Hook ID no encontrado para desinstalar: " + hookId);
        return false;
    }

    HookInfo& info = it->second;

    // Si no está hookeado, no hacer nada
    if (!info.isHooked || !info.originalFunc) {
        return true;
    }

    // Desinstalar el hook
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG error = DetourDetach(&info.originalFunc, info.hookFunc);
    LONG commitError = DetourTransactionCommit();

    if (error != NO_ERROR || commitError != NO_ERROR) {
        Log("Error al desinstalar hook: " + std::to_string(error) + ", " + std::to_string(commitError));
        return false;
    }

    info.isHooked = false;
    Log("Hook desinstalado: " + hookId);

    return true;
}

void HookManager::InstallAllHooks() {
    for (auto& pair : hooks) {
        InstallHook(pair.first);
    }
}

void HookManager::UnhookAll() {
    for (auto& pair : hooks) {
        if (pair.second.isHooked) {
            UninstallHook(pair.first);
        }
    }
}