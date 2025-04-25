#include "pch.h"
#include "HookManager.h"
#include "InternalHookManager.h"

// Clase para gestionar los hooks


//=============================================================================
// Ejemplos de hooks para diferentes funciones
//=============================================================================

// Tipo de la función GetProtocolID
typedef unsigned short(__thiscall* GetProtocolID_t)(void* thisPtr);

// Función hook para GetProtocolID
unsigned short __fastcall HookedGetProtocolID(void* thisPtr, void* edx) {
    // Obtener la función original
    GetProtocolID_t original = HookManager::GetInstance()->GetOriginalFunction<GetProtocolID_t>("GetProtocolID");

    // Llamar a la función original
    unsigned short protocolID = original(thisPtr);

    // Registrar el protocolo
    HookManager::GetInstance()->Log("[HOOK] Protocolo detectado: 0x" + std::to_string(protocolID));

    // Devolver el resultado original
    return protocolID;
}

// Tipo de la función Encript
typedef bool(__thiscall* Encript_t)(void* thisPtr, unsigned int param1);

// Función hook para Encript
bool __fastcall HookedEncript(void* thisPtr, void* edx, unsigned int param1) {
    // Obtener la función original
    Encript_t original = HookManager::GetInstance()->GetOriginalFunction<Encript_t>("Encript");

    // Registrar la llamada a la función
    HookManager::GetInstance()->Log("[HOOK] Encript llamado con param: " + std::to_string(param1));

    // Llamar a la función original
    bool result = original(thisPtr, param1);

    // Registrar el resultado
    HookManager::GetInstance()->Log("[HOOK] Encript resultado: " + std::string(result ? "true" : "false"));

    return result;
}

// Función para crear la consola de depuración
void CreateConsole() {
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);

    SetConsoleTitleA("Hook Manager Console");
    std::cout.clear();
    std::clog.clear();
    std::cerr.clear();
    std::cin.clear();
}


// Función adaptadora para la función de log de HookManager
void HookManagerLogAdapter(void* manager, const std::string& message) {
    // Convertir el puntero genérico a HookManager
    HookManager* hookManager = static_cast<HookManager*>(manager);

    // Llamar a la función de log de HookManager
    hookManager->Log(message);
}

// Función para registrar un hook interno
//void InitializeInternalHooks() {
//    // Obtener instancias de los managers
//    HookManager* hookManager = HookManager::GetInstance();
//    InternalHookManager* internalHookManager = InternalHookManager::GetInstance();
//
//    // Configurar InternalHookManager para usar el log de HookManager
//    internalHookManager->SetHookManager(hookManager, HookManagerLogAdapter);
//
//    //=============================================================================
//    // Registro de hooks internos usando diferentes métodos
//    //=============================================================================
//
//    // 1. Registro usando una dirección conocida (obtenida mediante depuración)
//    // Este método es útil cuando ya conoces la dirección exacta de la función
//    void* calculatedDamageAddress = (void*)0x12345678; // Ejemplo - reemplazar con dirección real
//    internalHookManager->RegisterHook(
//        "CalculateDamage",            // ID único
//        calculatedDamageAddress,      // Dirección conocida
//        "CalculateDamage",            // Nombre descriptivo
//        (void*)HookedCalculateDamage  // Función hook
//    );
//
//    // 2. Registro usando un patrón de bytes
//    // Este método es más flexible y resistente a actualizaciones del programa
//    internalHookManager->RegisterHook(
//        "RenderObject",               // ID único
//        "EngineRenderer.dll",         // Módulo donde buscar
//        "RenderObject",               // Nombre descriptivo
//        "pattern:55 8B EC 83 EC 14 53 56 57 8B F9 8B 5D 08", // Patrón hexadecimal
//        (void*)HookedRenderObject     // Función hook
//    );
//
//    // 3. Registro usando una dirección hexadecimal como string
//    // Este método es similar al primero pero usando formato de string
//    internalHookManager->RegisterHook(
//        "PhysicsCalculation",         // ID único
//        "PhysicsEngine.dll",          // Módulo donde buscar
//        "PhysicsCalculation",         // Nombre descriptivo
//        "0x40ABC123",                 // Dirección en formato hexadecimal
//        nullptr                       // No instalamos este hook en este ejemplo
//    );
//
//    // Instalar todos los hooks internos registrados
//    internalHookManager->InstallAllHooks();
//
//    hookManager->Log("Hooks internos inicializados correctamente");
//}


// Función principal para inicializar los hooks
extern "C" __declspec(dllexport) void Init() {
    // Registrar hooks para las funciones que nos interesan
    HookManager* hookManager = HookManager::GetInstance();

    // Registrar hook para GetProtocolID
    hookManager->RegisterHook(
        "GetProtocolID",                             // ID único del hook
        "I3NETWORKDX.DLL",                           // Nombre de la DLL
        "GetProtocolID",                             // Nombre de la función
        "?GetProtocolID@i3NetworkPacket@@QAEGXZ",    // Nombre decorado (opcional)
        (void*)HookedGetProtocolID                   // Función hook
    );

    // Ejemplo: Registrar otro hook (SendPacket)
    hookManager->RegisterHook(
        "Encript",                                   // ID único del hook
        "I3NETWORKDX.DLL",                           // Nombre de la DLL
        "Encript",                                   // Nombre de la función
        "?Encript@i3NetworkPacket@@QAEHI@Z",        // Nombre decorado
        (void*)HookedEncript                         // Función hook
    );

    // También podrías cargar la configuración de hooks desde un archivo de texto o ini

    // Instalar todos los hooks registrados
    hookManager->InstallAllHooks();
}

// Punto de entrada de la DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateConsole();
        Init();
        break;

    case DLL_PROCESS_DETACH:
        // Limpiar y desinstalar hooks
        if (HookManager::GetInstance()) {
            HookManager::GetInstance()->UnhookAll();
        }
        break;
    }
    return TRUE;
}