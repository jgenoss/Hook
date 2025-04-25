#include "pch.h"
#include "InternalHookManager.h"



// Inicializar el singleton
InternalHookManager* InternalHookManager::instance = nullptr;

InternalHookManager::InternalHookManager() {
    // Inicialización
    hookManager = nullptr;
    logFunc = nullptr;
    logFile.open("internal_hooks_log.txt", std::ios::app);
}

InternalHookManager* InternalHookManager::GetInstance() {
    if (!instance) {
        instance = new InternalHookManager();
    }
    return instance;
}

InternalHookManager::~InternalHookManager() {
    // Remover todos los hooks antes de destruir
    UnhookAll();

    if (logFile.is_open()) {
        logFile.close();
    }
}

void InternalHookManager::InternalLog(const std::string& message) {
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

void InternalHookManager::SetHookManager(void* manager, LogFunction logFn) {
    hookManager = manager;
    logFunc = logFn;
    Log("InternalHookManager inicializado y conectado a HookManager");
}

void InternalHookManager::Log(const std::string& message) {
    // Si tenemos HookManager, usar su función de log
    if (hookManager && logFunc) {
        logFunc(hookManager, "[Internal] " + message);
    }
    else {
        // De lo contrario, usar nuestro propio log
        InternalLog(message);
    }
}

void* InternalHookManager::FindPattern(const char* pattern, const char* mask, void* start, size_t size) {
    size_t patternLength = strlen(mask);

    // Iterar a través de la memoria buscando el patrón
    for (size_t i = 0; i < size - patternLength; i++) {
        bool found = true;

        for (size_t j = 0; j < patternLength; j++) {
            // Si el carácter actual en la máscara es '?', ignoramos esta posición
            if (mask[j] == '?' || pattern[j] == *(char*)((uintptr_t)start + i + j)) {
                continue;
            }

            found = false;
            break;
        }

        if (found) {
            return (void*)((uintptr_t)start + i);
        }
    }

    return nullptr;
}

void* InternalHookManager::FindFunctionByPattern(const char* pattern, const char* mask, const char* moduleName) {
    HMODULE moduleHandle = nullptr;

    if (moduleName) {
        moduleHandle = GetModuleHandleA(moduleName);
        if (!moduleHandle) {
            Log("Error: No se encontró el módulo en memoria: " + std::string(moduleName));
            return nullptr;
        }
    }
    else {
        // Si no se especifica un módulo, usamos el módulo principal
        moduleHandle = GetModuleHandleA(NULL);
    }

    // Obtener información del módulo
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(moduleInfo))) {
        Log("Error: No se pudo obtener información del módulo");
        return nullptr;
    }

    // Buscar el patrón en la memoria del módulo
    void* result = FindPattern(pattern, mask, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage);

    if (result) {
        Log("Patrón encontrado en dirección 0x" + std::to_string(reinterpret_cast<uintptr_t>(result)));
    }
    else {
        Log("No se encontró el patrón en la memoria del módulo");
    }

    return result;
}

bool InternalHookManager::HexStringToPattern(const std::string& hexStr, std::vector<char>& pattern, std::string& mask) {
    pattern.clear();
    mask.clear();

    // Procesar cada par de caracteres hexadecimales
    for (size_t i = 0; i < hexStr.length(); i++) {
        // Saltar espacios en blanco
        if (std::isspace(hexStr[i])) {
            continue;
        }

        // Verificar si es un comodín (?)
        if (hexStr[i] == '?') {
            pattern.push_back(0);  // Valor arbitrario, no importa
            mask.push_back('?');

            // Saltar el siguiente carácter si también es parte del comodín
            if (i + 1 < hexStr.length() && hexStr[i + 1] == '?') {
                i++;
            }
            continue;
        }

        // Verificar si tenemos suficientes caracteres para un byte
        if (i + 1 >= hexStr.length()) {
            Log("Error: String hexadecimal incompleto");
            return false;
        }

        // Convertir dos caracteres a un byte
        std::string byteStr = hexStr.substr(i, 2);
        try {
            char byte = static_cast<char>(std::stoi(byteStr, nullptr, 16));
            pattern.push_back(byte);
            mask.push_back('x');
        }
        catch (const std::exception&) {
            Log("Error: Formato hexadecimal inválido: " + byteStr);
            return false;
        }

        // Avanzar al siguiente par
        i++;
    }

    return !pattern.empty();
}

void* InternalHookManager::FindFunctionByHexPattern(const std::string& hexPattern, const char* moduleName) {
    std::vector<char> pattern;
    std::string mask;

    // Convertir el string hexadecimal a patrón y máscara
    if (!HexStringToPattern(hexPattern, pattern, mask)) {
        Log("Error: No se pudo convertir el patrón hexadecimal");
        return nullptr;
    }

    // Buscar el patrón
    return FindFunctionByPattern(pattern.data(), mask.c_str(), moduleName);
}

void* InternalHookManager::ProcessPatternOrAddress(const std::string& patternOrAddress, const char* moduleName) {
    // Si comienza con "0x", es una dirección directa
    if (patternOrAddress.substr(0, 2) == "0x") {
        try {
            uintptr_t address = std::stoull(patternOrAddress.substr(2), nullptr, 16);
            return reinterpret_cast<void*>(address);
        }
        catch (const std::exception&) {
            Log("Error: Formato de dirección inválido: " + patternOrAddress);
            return nullptr;
        }
    }

    // Si comienza con "pattern:", es un patrón hexadecimal
    if (patternOrAddress.substr(0, 8) == "pattern:") {
        return FindFunctionByHexPattern(patternOrAddress.substr(8), moduleName);
    }

    // Si no es ninguno de los anteriores, intentar como un nombre exportado
    if (moduleName) {
        HMODULE hModule = GetModuleHandleA(moduleName);
        if (hModule) {
            return GetProcAddress(hModule, patternOrAddress.c_str());
        }
    }

    return nullptr;
}

bool InternalHookManager::RegisterHook(const std::string& hookId, void* targetAddress,
    const std::string& funcName, void* hookFunction) {
    // Verificar si ya existe este hook
    if (internalHooks.find(hookId) != internalHooks.end()) {
        Log("Error: Hook ID ya existe: " + hookId);
        return false;
    }

    // Verificar que tengamos una dirección válida
    if (!targetAddress) {
        Log("Error: Dirección de función interna no válida para " + hookId);
        return false;
    }

    // Inicializar información del hook
    InternalHookInfo info;
    info.moduleName = "";
    info.funcName = funcName;
    info.patternOrAddress = "0x" + std::to_string(reinterpret_cast<uintptr_t>(targetAddress));
    info.originalFunc = targetAddress;
    info.hookFunc = hookFunction;
    info.isHooked = false;

    // Registrar el hook
    internalHooks[hookId] = info;
    Log("Hook interno registrado: " + hookId + " para dirección 0x" +
        std::to_string(reinterpret_cast<uintptr_t>(targetAddress)) + " (" + funcName + ")");

    return true;
}

bool InternalHookManager::RegisterHook(const std::string& hookId, const std::string& moduleName,
    const std::string& funcName, const std::string& patternOrAddress,
    void* hookFunction) {
    // Verificar si ya existe este hook
    if (internalHooks.find(hookId) != internalHooks.end()) {
        Log("Error: Hook ID ya existe: " + hookId);
        return false;
    }

    // Inicializar información del hook
    InternalHookInfo info;
    info.moduleName = moduleName;
    info.funcName = funcName;
    info.patternOrAddress = patternOrAddress;
    info.originalFunc = nullptr;  // Se asignará durante la instalación
    info.hookFunc = hookFunction;
    info.isHooked = false;

    // Registrar el hook
    internalHooks[hookId] = info;
    Log("Hook interno registrado: " + hookId + " para función " + funcName +
        " usando " + patternOrAddress);

    return true;
}

bool InternalHookManager::InstallHook(const std::string& hookId) {
    // Verificar si existe el hook
    auto it = internalHooks.find(hookId);
    if (it == internalHooks.end()) {
        Log("Error: Hook ID no encontrado: " + hookId);
        return false;
    }

    InternalHookInfo& info = it->second;

    // Si ya está hookeado, no hacer nada
    if (info.isHooked) {
        Log("Hook ya instalado: " + hookId);
        return true;
    }

    // Si no tenemos la dirección, intentar encontrarla
    if (!info.originalFunc) {
        info.originalFunc = ProcessPatternOrAddress(info.patternOrAddress,
            info.moduleName.empty() ? nullptr : info.moduleName.c_str());

        if (!info.originalFunc) {
            Log("Error: No se pudo obtener la dirección de la función para " + hookId);
            return false;
        }

        Log("Función " + info.funcName + " encontrada en dirección 0x" +
            std::to_string(reinterpret_cast<uintptr_t>(info.originalFunc)));
    }

    // Instalar el hook
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG error = DetourAttach(&info.originalFunc, info.hookFunc);
    LONG commitError = DetourTransactionCommit();

    if (error != NO_ERROR || commitError != NO_ERROR) {
        Log("Error al instalar hook interno: " + std::to_string(error) + ", " +
            std::to_string(commitError));
        return false;
    }

    info.isHooked = true;
    Log("Hook interno instalado exitosamente: " + hookId);

    return true;
}

bool InternalHookManager::UninstallHook(const std::string& hookId) {
    // Verificar si existe el hook
    auto it = internalHooks.find(hookId);
    if (it == internalHooks.end()) {
        Log("Error: Hook ID no encontrado para desinstalar: " + hookId);
        return false;
    }

    InternalHookInfo& info = it->second;

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
        Log("Error al desinstalar hook interno: " + std::to_string(error) + ", " +
            std::to_string(commitError));
        return false;
    }

    info.isHooked = false;
    Log("Hook interno desinstalado: " + hookId);

    return true;
}

void InternalHookManager::InstallAllHooks() {
    for (auto& pair : internalHooks) {
        InstallHook(pair.first);
    }
}

void InternalHookManager::UnhookAll() {
    for (auto& pair : internalHooks) {
        if (pair.second.isHooked) {
            UninstallHook(pair.first);
        }
    }
}